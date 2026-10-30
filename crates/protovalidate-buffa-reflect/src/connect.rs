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

use crate::{Failure, Plan, Validator};

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
    /// Each method's input type and its plan, by procedure path
    /// (`/pkg.Service/Method`), resolved once.
    inputs: HashMap<String, (MessageIndex, Plan)>,
}

impl ValidateInterceptor {
    #[must_use]
    pub fn new(pool: Arc<DescriptorPool>) -> Self {
        let validator = Validator::new();
        let inputs = pool
            .services()
            .iter()
            .flat_map(|s| {
                let (pool, validator) = (&pool, &validator);
                s.methods().iter().map(move |m| {
                    let plan = validator.plan(pool, m.input());
                    (
                        format!("/{}/{}", s.full_name(), m.name()),
                        (m.input(), plan),
                    )
                })
            })
            .collect();
        Self(Arc::new(Inner { pool, inputs }))
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
            Some((input, plan)) => self.0.check(*input, plan, payload),
            None => Ok(()),
        }
    }
}

impl Inner {
    fn check(
        &self,
        input: MessageIndex,
        plan: &Plan,
        payload: &Payload,
    ) -> Result<(), ConnectError> {
        let Ok(bytes) = payload.encoded() else {
            return Ok(());
        };
        let result = match payload.format() {
            CodecFormat::Proto => plan.run(&bytes),
            CodecFormat::Json => match std::str::from_utf8(&bytes).ok().and_then(|json| {
                DynamicMessage::from_json(Arc::clone(&self.pool), input, json).ok()
            }) {
                Some(message) => plan.run(&message.encode_to_vec()),
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
        let Some((input, plan)) = req.ctx.path().and_then(|p| self.0.inputs.get(p)) else {
            return next.run(req, inbound).await;
        };
        let (input, plan) = (*input, plan.clone());
        let inner = Arc::clone(&self.0);
        let inbound: PayloadStream = Box::pin(inbound.map(move |payload| {
            let payload = payload?;
            inner.check(input, &plan, &payload)?;
            Ok(payload)
        }));
        next.run(req, inbound).await
    }
}
