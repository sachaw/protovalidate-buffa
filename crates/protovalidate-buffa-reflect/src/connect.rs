//! Validating Connect requests.

use std::{collections::HashMap, sync::Arc};

use buffa::Message;
use buffa_descriptor::{
    DescriptorPool, MessageIndex,
    reflect::{DynamicMessage, ReflectMessage},
};
use connectrpc::{
    CodecFormat, ConnectError, Interceptor, Payload,
    interceptor::{
        Next, NextStream, PayloadStream, StreamRequest, StreamResponse, UnaryRequest, UnaryResponse,
    },
};
use futures_util::StreamExt as _;

use crate::{Failure, Validator};

impl Validator {
    /// Validates a request in a handler, as an `invalid_argument` error
    /// carrying the violations (see
    /// [`ValidationError::into_connect_error`](crate::ValidationError::into_connect_error)).
    ///
    /// # Errors
    ///
    /// The request is invalid, or its rules cannot be evaluated.
    pub fn check<M: Message + ReflectMessage>(&self, request: &M) -> Result<(), ConnectError> {
        self.validate(request)
            .map_err(protovalidate_buffa::ValidationError::into_connect_error)
    }
}

/// A Connect interceptor that validates every request message of the
/// services a descriptor pool describes, before the handler runs.
///
/// The interceptor sees the request before it is decoded, as bytes, and
/// validates the bytes without decoding them, so an invalid request is
/// rejected before the handler decodes it. A JSON request is decoded as a
/// [`DynamicMessage`] from the method's input descriptor and validated
/// through its encoding. Requests to methods the pool does not describe,
/// and bodies that do not decode, pass through to the handler, which
/// reports them.
///
/// ```ignore
/// let pool = Arc::clone(my_api::__buffa::reflect::descriptor_pool());
/// let service = service.with_interceptor(ValidateInterceptor::new(pool));
/// ```
pub struct ValidateInterceptor(Arc<Inner>);

struct Inner {
    pool: Arc<DescriptorPool>,
    /// Each method's input type, by procedure path (`/pkg.Service/Method`).
    inputs: HashMap<String, MessageIndex>,
    validator: Validator,
}

impl ValidateInterceptor {
    #[must_use]
    pub fn new(pool: Arc<DescriptorPool>) -> Self {
        let inputs = pool
            .services()
            .iter()
            .flat_map(|s| {
                s.methods()
                    .iter()
                    .map(move |m| (format!("/{}/{}", s.full_name(), m.name()), m.input()))
            })
            .collect();
        Self(Arc::new(Inner {
            pool,
            inputs,
            validator: Validator::new(),
        }))
    }
}

impl ValidateInterceptor {
    /// Validates one request message of `procedure` (`/pkg.Service/Method`),
    /// as the interceptor does: for checking requests in other middleware.
    ///
    /// # Errors
    ///
    /// The request is invalid, or its rules cannot be evaluated.
    pub fn check(&self, procedure: &str, payload: &Payload) -> Result<(), ConnectError> {
        match self.0.inputs.get(procedure) {
            Some(&input) => self.0.check(input, payload),
            None => Ok(()),
        }
    }
}

impl Inner {
    fn check(&self, input: MessageIndex, payload: &Payload) -> Result<(), ConnectError> {
        let Ok(bytes) = payload.encoded() else {
            return Ok(());
        };
        let result = match payload.format() {
            CodecFormat::Proto => self.validator.validate_wire(&self.pool, input, &bytes),
            CodecFormat::Json => match std::str::from_utf8(&bytes).ok().and_then(|json| {
                DynamicMessage::from_json(Arc::clone(&self.pool), input, json).ok()
            }) {
                Some(message) => {
                    self.validator
                        .validate_wire(&self.pool, input, &message.encode_to_vec())
                }
                None => return Ok(()),
            },
            _ => return Ok(()),
        };
        match result {
            Ok(()) => Ok(()),
            Err(failure) => match *failure {
                Failure::Invalid(e) => Err(e.into_connect_error()),
                Failure::Malformed => Ok(()),
            },
        }
    }
}

#[connectrpc::async_trait]
impl Interceptor for ValidateInterceptor {
    async fn intercept_unary(
        &self,
        req: UnaryRequest,
        next: Next<'_>,
    ) -> Result<UnaryResponse, ConnectError> {
        if let Some(procedure) = req.ctx.path() {
            self.check(procedure, &req.payload)?;
        }
        next.run(req).await
    }

    async fn intercept_streaming(
        &self,
        req: StreamRequest,
        inbound: PayloadStream,
        next: NextStream<'_>,
    ) -> Result<StreamResponse, ConnectError> {
        let Some(&input) = req.ctx.path().and_then(|p| self.0.inputs.get(p)) else {
            return next.run(req, inbound).await;
        };
        let inner = Arc::clone(&self.0);
        let inbound: PayloadStream = Box::pin(inbound.map(move |payload| {
            let payload = payload?;
            inner.check(input, &payload)?;
            Ok(payload)
        }));
        next.run(req, inbound).await
    }
}
