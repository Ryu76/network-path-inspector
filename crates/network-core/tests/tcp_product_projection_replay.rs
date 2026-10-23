//! 부모가 작성한 공개 API 가시성 회귀. 소켓·DNS·runtime·프로세스 호출 없음.
#[test]
fn parent_public_projector_signature_contract() {
    let _projector: fn(&mut npi_core::FeatureResult, &network_core::TcpMeasurement) =
        npi_probes::engine::apply_tcp_result;
}
