// Two public validator sets for one type: inference cannot choose.
use geo_validate as _;

use geo_types::geo::v1::GeoPoint;
use protovalidate_buffa::{Validate, ValidationError};

enum Local {}

impl Validate<Local> for GeoPoint {
    fn validate(&self) -> Result<(), ValidationError> {
        Ok(())
    }
}

fn main() {
    let point = GeoPoint::default();
    let _ = point.validate();
}
