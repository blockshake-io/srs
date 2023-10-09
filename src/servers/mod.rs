use actix_web::{dev, middleware::ErrorHandlerResponse};
use log::warn;

pub mod indexer;
pub mod oracle;

/// log errors
fn error_logger<B>(res: dev::ServiceResponse<B>) -> actix_web::Result<ErrorHandlerResponse<B>> {
    match res.response().error() {
        Some(err) => {
            let req = res.request();
            warn!(
                "request \"{} {}\" failed with error: {}",
                req.method(),
                req.path(),
                err
            );
        }
        _ => {}
    }
    Ok(ErrorHandlerResponse::Response(res.map_into_left_body()))
}
