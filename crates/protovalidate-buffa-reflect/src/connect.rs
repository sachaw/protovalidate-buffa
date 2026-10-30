//! Validating Connect requests.

use std::{collections::HashMap, sync::Arc};

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

use crate::Validator;

impl Validator {
    /// Validates a request in a handler, as an `invalid_argument` error
    /// carrying the violations (see
    /// [`ValidationError::into_connect_error`](crate::ValidationError::into_connect_error)).
    ///
    /// # Errors
    ///
    /// The request is invalid, or its rules cannot be evaluated.
    pub fn check(&self, request: &dyn ReflectMessage) -> Result<(), ConnectError> {
        self.validate(request)
            .map_err(protovalidate_buffa::ValidationError::into_connect_error)
    }
}

/// A Connect interceptor that validates every request message of the
/// services a descriptor pool describes, before the handler runs.
///
/// The interceptor sees the request before it is decoded, as bytes, so it
/// decodes a [`DynamicMessage`] from the method's input descriptor to
/// validate. Requests to methods the pool does not describe, and bodies
/// that do not decode, pass through to the handler, which reports them.
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

impl Inner {
    fn check(&self, input: MessageIndex, payload: &Payload) -> Result<(), ConnectError> {
        let Ok(bytes) = payload.encoded() else {
            return Ok(());
        };
        let message = match payload.format() {
            CodecFormat::Proto => DynamicMessage::decode_with_options(
                Arc::clone(&self.pool),
                input,
                &bytes,
                payload.decode_options(),
            )
            .ok(),
            CodecFormat::Json => std::str::from_utf8(&bytes).ok().and_then(|json| {
                DynamicMessage::from_json(Arc::clone(&self.pool), input, json).ok()
            }),
            _ => None,
        };
        match message {
            Some(message) => self.validator.check(&message),
            None => Ok(()),
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
        if let Some(&input) = req.ctx.path().and_then(|p| self.0.inputs.get(p)) {
            self.0.check(input, &req.payload)?;
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
