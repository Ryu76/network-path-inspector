//! `npi_probes::host` 순수 변환 단위 시험 및 부모 전용(`#[ignore]`) 네이티브 스냅샷 시험.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use npi_probes::host::{
    ADAPTER_PARTIAL_LIMITATION_PREFIX, AdapterEntry, HostSnapshot, INITIAL_ADAPTER_BUFFER_BYTES,
    MAX_ADAPTER_BUFFER_BYTES, MAX_BUFFER_OVERFLOW_RETRIES, PrefixEntry, RouteEntry,
    SELECTED_ROUTE_LIMITATION, SNAPSHOT_READONLY_LIMITATION, UnicastAddressEntry,
    adapter_partial_errors, adapter_partial_errors_from_limitations, aligned_usize_word_count,
    build_host_snapshot_from_parts, build_selected_route_entry, build_selected_route_value,
    collect_host_snapshot, format_cidr, ipv4_from_network_u32, ipv4_to_network_u32,
    is_range_within_buffer, next_overflow_buffer_size, oper_status_label, read_bounded_ascii,
    read_bounded_utf16,
};
use serde_json::Value;

#[test]
fn overflow_retry_policy_respects_4mib_and_retry_bounds() {
    let next = next_overflow_buffer_size(INITIAL_ADAPTER_BUFFER_BYTES, 65_536, 0)
        .expect("유효한 버퍼 확장 요청은 성공해야 합니다");
    assert_eq!(next, 65_536);

    let max_ok = next_overflow_buffer_size(65_536, MAX_ADAPTER_BUFFER_BYTES as u32, 1)
        .expect("정확히 4MiB인 요청은 허용되어야 합니다");
    assert_eq!(max_ok, MAX_ADAPTER_BUFFER_BYTES);

    let over_4mib = next_overflow_buffer_size(65_536, (MAX_ADAPTER_BUFFER_BYTES as u32) + 8, 1);
    assert!(
        over_4mib.is_err(),
        "4MiB 초과 버퍼 요청은 거부되어야 합니다"
    );

    let zero_req = next_overflow_buffer_size(INITIAL_ADAPTER_BUFFER_BYTES, 0, 0);
    assert!(zero_req.is_err(), "0 바이트 버퍼 요청은 거부되어야 합니다");

    let exhausted = next_overflow_buffer_size(
        INITIAL_ADAPTER_BUFFER_BYTES,
        65_536,
        MAX_BUFFER_OVERFLOW_RETRIES,
    );
    assert!(
        exhausted.is_err(),
        "재시도 상한 도달 시 오류가 반환되어야 합니다"
    );
}

#[test]
fn aligned_buffer_and_range_validation_prevent_overrun() {
    let words = aligned_usize_word_count(33);
    assert!(words * std::mem::size_of::<usize>() >= 33);

    let base = 0x1000usize;
    let total = 256usize;
    assert!(is_range_within_buffer(base, total, 0x1000, 64, 32));
    assert!(is_range_within_buffer(base, total, 0x10C0, 64, 64));
    assert!(!is_range_within_buffer(base, total, 0x10C1, 64, 64));
    assert!(!is_range_within_buffer(base, total, 0x0FFF, 16, 16));
    assert!(!is_range_within_buffer(base, total, 0, 16, 16));
    assert!(!is_range_within_buffer(base, total, 0x1000, 16, 32));
}

#[test]
fn bounded_strings_and_status_labels_convert_cleanly() {
    let raw_ascii = b"eth0\0trailing";
    assert_eq!(read_bounded_ascii(raw_ascii, 16), "eth0");
    assert_eq!(read_bounded_ascii(b"abcdef", 4), "abcd");

    let utf16_units: Vec<u16> = "루프백\0무시됨".encode_utf16().collect();
    assert_eq!(read_bounded_utf16(&utf16_units, 32), "루프백");
    let truncated_units: Vec<u16> = "가나다라마".encode_utf16().collect();
    assert_eq!(read_bounded_utf16(&truncated_units, 3), "가나다");

    assert_eq!(oper_status_label(1), "UP");
    assert_eq!(oper_status_label(2), "DOWN");
    assert_eq!(oper_status_label(6), "NOT_PRESENT");
    assert_eq!(oper_status_label(999), "OTHER");
}

#[test]
fn ipv4_network_order_and_cidr_formatting_are_exact() {
    let ip = Ipv4Addr::new(127, 0, 0, 1);
    let raw = ipv4_to_network_u32(ip);
    assert_eq!(raw.to_ne_bytes(), [127, 0, 0, 1]);
    assert_eq!(ipv4_from_network_u32(raw), ip);

    assert_eq!(format_cidr(IpAddr::V4(ip), 8), "127.0.0.1/8");
    assert_eq!(format_cidr(IpAddr::V6(Ipv6Addr::LOCALHOST), 128), "::1/128");
}

#[test]
fn selected_route_and_snapshot_preserve_fields_and_non_connectivity_semantics() {
    let route = RouteEntry {
        destination_prefix: "127.0.0.0/8".to_string(),
        prefix: "127.0.0.0/8".to_string(),
        prefix_ip: "127.0.0.0".to_string(),
        prefix_length: 8,
        next_hop: "0.0.0.0".to_string(),
        metric: 256,
        interface_index: 1,
        interface_luid: 42,
        protocol: 2,
        origin: 1,
        loopback: true,
    };
    let target = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let source = IpAddr::V4(Ipv4Addr::LOCALHOST);

    let selected_val = build_selected_route_value(target, source, &route);
    assert_eq!(selected_val["target"], "127.0.0.1");
    assert_eq!(selected_val["source_ip"], "127.0.0.1");
    assert_eq!(selected_val["interface_index"], 1);
    assert_eq!(selected_val["prefix"], "127.0.0.0/8");
    assert_eq!(selected_val["next_hop"], "0.0.0.0");
    assert_eq!(selected_val["metric"], 256);
    assert_eq!(selected_val["selection_basis"], "OS_ROUTE_SELECTION");
    assert_eq!(selected_val["remote_connectivity_evidence"], false);
    assert!(
        selected_val["note"]
            .as_str()
            .is_some_and(|s| s.contains("OS route selection"))
    );

    let adapter = AdapterEntry {
        interface_index: 1,
        ipv6_interface_index: 1,
        name: "Loopback Pseudo-Interface 1".to_string(),
        adapter_name: "{LOOPBACK}".to_string(),
        friendly_name: "Loopback Pseudo-Interface 1".to_string(),
        description: "Software Loopback Interface 1".to_string(),
        dns_suffix: String::new(),
        operational_status: "UP".to_string(),
        oper_status_code: 1,
        ips: vec!["127.0.0.1".to_string(), "::1".to_string()],
        unicast_addresses: vec![
            UnicastAddressEntry {
                ip: "127.0.0.1".to_string(),
                prefix_length: 8,
            },
            UnicastAddressEntry {
                ip: "::1".to_string(),
                prefix_length: 128,
            },
        ],
        prefixes: vec!["127.0.0.0/8".to_string(), "::1/128".to_string()],
        prefix_entries: vec![PrefixEntry {
            prefix: "127.0.0.0".to_string(),
            prefix_length: 8,
            cidr: "127.0.0.0/8".to_string(),
        }],
        gateways: Vec::new(),
        dns_servers: vec!["::1".to_string()],
    };

    let selected_entry = build_selected_route_entry(target, source, &route);
    let snapshot = build_host_snapshot_from_parts(
        Some(vec![adapter]),
        Some(vec![route]),
        Some(selected_entry),
        Vec::new(),
        Vec::new(),
    );

    let serialized = serde_json::to_value(&snapshot).expect("HostSnapshot 직렬화 성공");
    assert!(
        serialized.get("capture").is_none(),
        "capture 필드를 생성하면 안 됩니다"
    );
    assert!(snapshot.adapters.is_array());
    assert!(snapshot.routes.is_array());
    assert!(snapshot.selected_route.is_object());
    assert!(snapshot.errors.is_empty());
    assert!(
        snapshot
            .limitations
            .iter()
            .any(|l| l == SELECTED_ROUTE_LIMITATION)
    );
    assert!(
        snapshot
            .limitations
            .iter()
            .any(|l| l == SNAPSHOT_READONLY_LIMITATION)
    );

    let roundtrip: HostSnapshot =
        serde_json::from_value(serialized).expect("HostSnapshot 역직렬화 성공");
    assert_eq!(roundtrip, snapshot);
}

#[test]
fn failed_components_remain_null_with_explicit_errors() {
    let snapshot = build_host_snapshot_from_parts(
        None,
        Some(Vec::new()),
        None,
        vec![
            "GetAdaptersAddresses 실패".to_string(),
            "GetBestRoute2 실패".to_string(),
        ],
        Vec::new(),
    );
    assert_eq!(snapshot.adapters, Value::Null);
    assert_eq!(snapshot.routes, serde_json::json!([]));
    assert_eq!(snapshot.selected_route, Value::Null);
    assert_eq!(snapshot.errors.len(), 2);
}

#[test]
fn adapter_partial_errors_only_count_partial_marker() {
    let none = adapter_partial_errors(&[
        "어댑터(IfIndex 1): FirstPrefix 목록에서 해석된 프리픽스가 없어 파생 표시값으로 채웠습니다"
            .to_string(),
        SELECTED_ROUTE_LIMITATION.to_string(),
    ]);
    assert!(
        none.is_empty(),
        "부분 수집 접두어가 없는 제한사항은 오류로 승격하지 않아야 합니다"
    );

    let partial = adapter_partial_errors(&[
        format!("{ADAPTER_PARTIAL_LIMITATION_PREFIX} 합성 순환 제한사항"),
        format!("{ADAPTER_PARTIAL_LIMITATION_PREFIX} 합성 절단 제한사항"),
    ]);
    assert_eq!(partial.len(), 1, "부분 수집 오류는 1건으로 요약되어야 합니다");
    assert!(partial[0].contains("2건"));
    assert!(partial[0].contains("부분적으로만 수집"));

    let partial_alias = adapter_partial_errors_from_limitations(&[
        format!("{ADAPTER_PARTIAL_LIMITATION_PREFIX} 합성 순환 제한사항"),
        format!("{ADAPTER_PARTIAL_LIMITATION_PREFIX} 합성 절단 제한사항"),
    ]);
    assert_eq!(partial_alias, partial);
}

#[cfg(windows)]
mod windows_pure_tests {
    use super::*;
    use npi_probes::host::{
        ip_from_sockaddr_inet, parse_adapters_from_aligned_buffer, route_entry_from_mib_row,
        sockaddr_inet_from_ip,
    };
    use windows_sys::Win32::{
        NetworkManagement::{
            IpHelper::{
                IP_ADAPTER_ADDRESSES_LH, IP_ADAPTER_DNS_SERVER_ADDRESS_XP,
                IP_ADAPTER_GATEWAY_ADDRESS_LH, IP_ADAPTER_PREFIX_XP, IP_ADAPTER_UNICAST_ADDRESS_LH,
                MIB_IPFORWARD_ROW2,
            },
            Ndis::IfOperStatusUp,
        },
        Networking::WinSock::{
            AF_INET, AF_INET6, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKET_ADDRESS,
        },
    };

    #[test]
    fn sockaddr_inet_and_mib_row_conversions_preserve_loopback_fields() {
        let v4 = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let inet_v4 = sockaddr_inet_from_ip(v4);
        assert_eq!(ip_from_sockaddr_inet(&inet_v4), Some(v4));

        let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let inet_v6 = sockaddr_inet_from_ip(v6);
        assert_eq!(ip_from_sockaddr_inet(&inet_v6), Some(v6));

        // SAFETY: 테스트용 MIB_IPFORWARD_ROW2 구조체를 0 초기화한다.
        let mut row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
        row.InterfaceIndex = 1;
        row.InterfaceLuid.Value = 0x1000_0000_0000_0001;
        row.DestinationPrefix.Prefix =
            sockaddr_inet_from_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)));
        row.DestinationPrefix.PrefixLength = 8;
        row.NextHop = sockaddr_inet_from_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        row.Metric = 256;
        row.Protocol = 2;
        row.Origin = 1;
        row.Loopback = true;

        let entry = route_entry_from_mib_row(&row).expect("유효한 MIB_IPFORWARD_ROW2 변환 성공");
        assert_eq!(entry.prefix, "127.0.0.0/8");
        assert_eq!(entry.destination_prefix, "127.0.0.0/8");
        assert_eq!(entry.prefix_ip, "127.0.0.0");
        assert_eq!(entry.prefix_length, 8);
        assert_eq!(entry.next_hop, "0.0.0.0");
        assert_eq!(entry.metric, 256);
        assert_eq!(entry.interface_index, 1);
        assert!(entry.loopback);
    }

    #[test]
    fn aligned_buffer_parser_extracts_adapter_and_stops_on_cycle() {
        let total_bytes = 4096usize;
        let mut buf = vec![0usize; aligned_usize_word_count(total_bytes)];
        let base_ptr = buf.as_mut_ptr().cast::<u8>();

        // 버퍼 내 오프셋 배치:
        // 0: IP_ADAPTER_ADDRESSES_LH
        // 512: IP_ADAPTER_UNICAST_ADDRESS_LH
        // 640: IP_ADAPTER_PREFIX_XP
        // 768: IP_ADAPTER_GATEWAY_ADDRESS_LH
        // 896: IP_ADAPTER_DNS_SERVER_ADDRESS_XP
        // 1024: SOCKADDR_IN (127.0.0.1)
        // 1088: SOCKADDR_IN (127.0.0.0)
        // 1152: AdapterName ("lo0\0")
        // 1216: FriendlyName ("Loopback\0" UTF-16)
        // SAFETY: 4096 바이트 정렬 버퍼 내부의 비중첩 오프셋에 테스트 구조체를 기록한다.
        unsafe {
            let sin_loopback_ptr = base_ptr.add(1024).cast::<SOCKADDR_IN>();
            let mut sin_loopback: SOCKADDR_IN = std::mem::zeroed();
            sin_loopback.sin_family = AF_INET;
            sin_loopback.sin_addr.S_un.S_addr = ipv4_to_network_u32(Ipv4Addr::LOCALHOST);
            sin_loopback_ptr.write_unaligned(sin_loopback);

            let sin_net_ptr = base_ptr.add(1088).cast::<SOCKADDR_IN>();
            let mut sin_net: SOCKADDR_IN = std::mem::zeroed();
            sin_net.sin_family = AF_INET;
            sin_net.sin_addr.S_un.S_addr = ipv4_to_network_u32(Ipv4Addr::new(127, 0, 0, 0));
            sin_net_ptr.write_unaligned(sin_net);

            let name_bytes = b"lo0\0";
            std::ptr::copy_nonoverlapping(
                name_bytes.as_ptr(),
                base_ptr.add(1152),
                name_bytes.len(),
            );

            let friendly_u16: Vec<u16> = "Loopback\0".encode_utf16().collect();
            std::ptr::copy_nonoverlapping(
                friendly_u16.as_ptr(),
                base_ptr.add(1216).cast::<u16>(),
                friendly_u16.len(),
            );

            let uni_ptr = base_ptr.add(512).cast::<IP_ADAPTER_UNICAST_ADDRESS_LH>();
            let mut uni: IP_ADAPTER_UNICAST_ADDRESS_LH = std::mem::zeroed();
            uni.Anonymous.Anonymous.Length =
                std::mem::size_of::<IP_ADAPTER_UNICAST_ADDRESS_LH>() as u32;
            uni.Address = SOCKET_ADDRESS {
                lpSockaddr: sin_loopback_ptr.cast::<SOCKADDR>(),
                iSockaddrLength: std::mem::size_of::<SOCKADDR_IN>() as i32,
            };
            uni.OnLinkPrefixLength = 8;
            uni_ptr.write_unaligned(uni);

            let pfx_ptr = base_ptr.add(640).cast::<IP_ADAPTER_PREFIX_XP>();
            let mut pfx: IP_ADAPTER_PREFIX_XP = std::mem::zeroed();
            pfx.Anonymous.Anonymous.Length = std::mem::size_of::<IP_ADAPTER_PREFIX_XP>() as u32;
            pfx.Address = SOCKET_ADDRESS {
                lpSockaddr: sin_net_ptr.cast::<SOCKADDR>(),
                iSockaddrLength: std::mem::size_of::<SOCKADDR_IN>() as i32,
            };
            pfx.PrefixLength = 8;
            pfx_ptr.write_unaligned(pfx);

            let gw_ptr = base_ptr.add(768).cast::<IP_ADAPTER_GATEWAY_ADDRESS_LH>();
            let mut gw: IP_ADAPTER_GATEWAY_ADDRESS_LH = std::mem::zeroed();
            gw.Anonymous.Anonymous.Length =
                std::mem::size_of::<IP_ADAPTER_GATEWAY_ADDRESS_LH>() as u32;
            gw.Address = SOCKET_ADDRESS {
                lpSockaddr: sin_loopback_ptr.cast::<SOCKADDR>(),
                iSockaddrLength: std::mem::size_of::<SOCKADDR_IN>() as i32,
            };
            gw_ptr.write_unaligned(gw);

            let dns_ptr = base_ptr.add(896).cast::<IP_ADAPTER_DNS_SERVER_ADDRESS_XP>();
            let mut dns: IP_ADAPTER_DNS_SERVER_ADDRESS_XP = std::mem::zeroed();
            dns.Anonymous.Anonymous.Length =
                std::mem::size_of::<IP_ADAPTER_DNS_SERVER_ADDRESS_XP>() as u32;
            dns.Address = SOCKET_ADDRESS {
                lpSockaddr: sin_loopback_ptr.cast::<SOCKADDR>(),
                iSockaddrLength: std::mem::size_of::<SOCKADDR_IN>() as i32,
            };
            dns_ptr.write_unaligned(dns);

            let adapter_ptr = base_ptr.cast::<IP_ADAPTER_ADDRESSES_LH>();
            let mut adapter: IP_ADAPTER_ADDRESSES_LH = std::mem::zeroed();
            adapter.Anonymous1.Anonymous.Length =
                std::mem::size_of::<IP_ADAPTER_ADDRESSES_LH>() as u32;
            adapter.Anonymous1.Anonymous.IfIndex = 1;
            adapter.Ipv6IfIndex = 1;
            adapter.AdapterName = base_ptr.add(1152);
            adapter.FriendlyName = base_ptr.add(1216).cast::<u16>();
            adapter.OperStatus = IfOperStatusUp;
            adapter.FirstUnicastAddress = uni_ptr;
            adapter.FirstPrefix = pfx_ptr;
            adapter.FirstGatewayAddress = gw_ptr;
            adapter.FirstDnsServerAddress = dns_ptr;
            // 자기 자신을 가리키는 순환 Next 포인터 주입
            adapter.Next = adapter_ptr;
            adapter_ptr.write_unaligned(adapter);
        }

        let mut limitations = Vec::new();
        let adapters = parse_adapters_from_aligned_buffer(&buf, total_bytes, &mut limitations);
        assert_eq!(adapters.len(), 1);
        let item = &adapters[0];
        assert_eq!(item.interface_index, 1);
        assert_eq!(item.name, "Loopback");
        assert_eq!(item.adapter_name, "lo0");
        assert_eq!(item.operational_status, "UP");
        assert_eq!(item.ips, vec!["127.0.0.1".to_string()]);
        assert_eq!(item.prefixes, vec!["127.0.0.0/8".to_string()]);
        assert_eq!(item.gateways, vec!["127.0.0.1".to_string()]);
        assert_eq!(item.dns_servers, vec!["127.0.0.1".to_string()]);
        assert!(
            limitations.iter().any(|l| l.contains("순환 포인터")),
            "순환 Next 포인터가 감지되어 기록되어야 합니다"
        );
    }

    #[test]
    fn aligned_buffer_parser_handles_malformed_short_buffer_and_invalid_lengths() {
        // 1. 어댑터 구조체 크기보다 현저히 작은 짧은 버퍼 (short-buffer, valid_bytes < sizeof(IP_ADAPTER_ADDRESSES_LH))
        let short_bytes = 32usize;
        let buf_short = vec![0usize; aligned_usize_word_count(512)];
        let mut lim_short = Vec::new();
        let adapters_short =
            parse_adapters_from_aligned_buffer(&buf_short, short_bytes, &mut lim_short);
        assert!(
            adapters_short.is_empty(),
            "어댑터 구조체 크기 미만 버퍼에서는 어댑터를 파싱하지 않아야 합니다"
        );
        assert!(
            lim_short
                .iter()
                .any(|l| l.contains(ADAPTER_PARTIAL_LIMITATION_PREFIX)
                    && l.contains("유효 버퍼 범위를 벗어나")),
            "짧은 버퍼에 대해 포인터 범위 초과 부분 수집 제한사항이 기록되어야 합니다"
        );
        let errs_short = adapter_partial_errors(&lim_short);
        assert_eq!(
            errs_short.len(),
            1,
            "짧은 버퍼 제한사항은 부분 수집 오류로 승격되어야 합니다"
        );

        // 2. 어댑터 Length 필드가 최소 구조체 크기 미만인 손상 버퍼 (malformed short length)
        let total_bytes = 2048usize;
        let mut buf_bad_len = vec![0usize; aligned_usize_word_count(total_bytes)];
        let base_bad = buf_bad_len.as_mut_ptr().cast::<u8>();
        unsafe {
            let adapter_ptr = base_bad.cast::<IP_ADAPTER_ADDRESSES_LH>();
            let mut adapter: IP_ADAPTER_ADDRESSES_LH = std::mem::zeroed();
            adapter.Anonymous1.Anonymous.Length = 16; // 최소 크기 미만
            adapter.Anonymous1.Anonymous.IfIndex = 2;
            adapter_ptr.write_unaligned(adapter);
        }
        let mut lim_bad_len = Vec::new();
        let adapters_bad_len =
            parse_adapters_from_aligned_buffer(&buf_bad_len, total_bytes, &mut lim_bad_len);
        assert!(
            adapters_bad_len.is_empty(),
            "최소 크기 미만의 Length를 가진 어댑터는 파싱되지 않아야 합니다"
        );
        assert!(
            lim_bad_len
                .iter()
                .any(|l| l.contains(ADAPTER_PARTIAL_LIMITATION_PREFIX)
                    && l.contains("Length 필드가")),
            "비정상 Length에 대한 부분 수집 제한사항이 기록되어야 합니다"
        );

        // 3. 어댑터 Length 필드가 유효 버퍼 바이트를 초과하는 손상 버퍼 (malformed overrun length)
        let mut buf_overrun = vec![0usize; aligned_usize_word_count(1024)];
        let base_overrun = buf_overrun.as_mut_ptr().cast::<u8>();
        unsafe {
            let adapter_ptr = base_overrun.cast::<IP_ADAPTER_ADDRESSES_LH>();
            let mut adapter: IP_ADAPTER_ADDRESSES_LH = std::mem::zeroed();
            adapter.Anonymous1.Anonymous.Length = 4096; // 버퍼 1024 초과
            adapter.Anonymous1.Anonymous.IfIndex = 3;
            adapter_ptr.write_unaligned(adapter);
        }
        let mut lim_overrun = Vec::new();
        let adapters_overrun =
            parse_adapters_from_aligned_buffer(&buf_overrun, 1024, &mut lim_overrun);
        assert!(
            adapters_overrun.is_empty(),
            "버퍼 범위를 초과하는 Length는 어댑터를 파싱하지 않아야 합니다"
        );
        assert!(
            lim_overrun
                .iter()
                .any(|l| l.contains(ADAPTER_PARTIAL_LIMITATION_PREFIX)
                    && l.contains("Length 필드가")),
            "버퍼 초과 Length에 대한 부분 수집 제한사항이 기록되어야 합니다"
        );

        // 4. 하위 리스트(유니캐스트) 노드의 Length 필드가 최소 크기 미만인 손상 버퍼 (malformed sublist length)
        let mut buf_sublist_bad = vec![0usize; aligned_usize_word_count(4096)];
        let base_sub = buf_sublist_bad.as_mut_ptr().cast::<u8>();
        unsafe {
            let adapter_ptr = base_sub.cast::<IP_ADAPTER_ADDRESSES_LH>();
            let mut adapter: IP_ADAPTER_ADDRESSES_LH = std::mem::zeroed();
            adapter.Anonymous1.Anonymous.Length =
                std::mem::size_of::<IP_ADAPTER_ADDRESSES_LH>() as u32;
            adapter.Anonymous1.Anonymous.IfIndex = 4;

            let uni_ptr = base_sub.add(512).cast::<IP_ADAPTER_UNICAST_ADDRESS_LH>();
            let mut uni: IP_ADAPTER_UNICAST_ADDRESS_LH = std::mem::zeroed();
            uni.Anonymous.Anonymous.Length = 4; // 최소 구조체 크기 미만 손상 Length
            uni_ptr.write_unaligned(uni);

            adapter.FirstUnicastAddress = uni_ptr;
            adapter_ptr.write_unaligned(adapter);
        }
        let mut lim_sublist = Vec::new();
        let adapters_sublist =
            parse_adapters_from_aligned_buffer(&buf_sublist_bad, 4096, &mut lim_sublist);
        assert_eq!(
            adapters_sublist.len(),
            1,
            "어댑터 헤더 자체는 정상이므로 1개 어댑터가 반환되어야 합니다"
        );
        assert!(
            adapters_sublist[0].ips.is_empty(),
            "손상된 하위 리스트 노드는 IP로 파싱되지 않아야 합니다"
        );
        assert!(
            lim_sublist.iter().any(|l| l
                .contains(ADAPTER_PARTIAL_LIMITATION_PREFIX)
                && l.contains("유니캐스트 주소 하위 목록: 노드 Length 필드(4)가")),
            "하위 리스트 손상 Length에 대한 부분 수집 제한사항이 기록되어야 합니다"
        );
        let errs_sublist = adapter_partial_errors(&lim_sublist);
        assert_eq!(errs_sublist.len(), 1);

        // 5. 하위 리스트 노드의 lpSockaddr 포인터가 버퍼 범위를 벗어난 손상 버퍼 (out-of-bounds socket address)
        let mut buf_oob_sock = vec![0usize; aligned_usize_word_count(4096)];
        let base_oob = buf_oob_sock.as_mut_ptr().cast::<u8>();
        unsafe {
            let adapter_ptr = base_oob.cast::<IP_ADAPTER_ADDRESSES_LH>();
            let mut adapter: IP_ADAPTER_ADDRESSES_LH = std::mem::zeroed();
            adapter.Anonymous1.Anonymous.Length =
                std::mem::size_of::<IP_ADAPTER_ADDRESSES_LH>() as u32;
            adapter.Anonymous1.Anonymous.IfIndex = 5;

            let uni_ptr = base_oob.add(512).cast::<IP_ADAPTER_UNICAST_ADDRESS_LH>();
            let mut uni: IP_ADAPTER_UNICAST_ADDRESS_LH = std::mem::zeroed();
            uni.Anonymous.Anonymous.Length =
                std::mem::size_of::<IP_ADAPTER_UNICAST_ADDRESS_LH>() as u32;
            // 유효 버퍼 범위(4096)를 훨씬 벗어난 포인터 (포인터 생성 자체의 미정의 동작(UB)을 방지하기 위해 wrapping_add 사용, 절대 역참조하지 않음)
            uni.Address = SOCKET_ADDRESS {
                lpSockaddr: base_oob.wrapping_add(50_000).cast::<SOCKADDR>(),
                iSockaddrLength: std::mem::size_of::<SOCKADDR_IN>() as i32,
            };
            uni_ptr.write_unaligned(uni);

            adapter.FirstUnicastAddress = uni_ptr;
            adapter_ptr.write_unaligned(adapter);
        }
        let mut lim_oob = Vec::new();
        let adapters_oob = parse_adapters_from_aligned_buffer(&buf_oob_sock, 4096, &mut lim_oob);
        assert_eq!(adapters_oob.len(), 1);
        assert!(adapters_oob[0].ips.is_empty());
        assert!(
            lim_oob.iter().any(|l| l
                .contains(ADAPTER_PARTIAL_LIMITATION_PREFIX)
                && l.contains("해석할 수 없는 소켓 주소 1건을 건너뛰었습니다")),
            "버퍼 밖 소켓 주소에 대한 건너뜀 부분 수집 제한사항이 기록되어야 합니다"
        );
        let errs_oob = adapter_partial_errors(&lim_oob);
        assert_eq!(errs_oob.len(), 1);
    }

    #[test]
    fn aligned_buffer_parser_handles_sublist_cycles_and_retains_earlier_rows() {
        let total_bytes = 8192usize;
        let mut buf = vec![0usize; aligned_usize_word_count(total_bytes)];
        let base_ptr = buf.as_mut_ptr().cast::<u8>();

        // 비중첩 안전 오프셋 배치:
        // 0: IP_ADAPTER_ADDRESSES_LH (어댑터 루트)
        // 512: uni_1 (IP_ADAPTER_UNICAST_ADDRESS_LH, 127.0.0.1 -> next: uni_2)
        // 640: uni_2 (IP_ADAPTER_UNICAST_ADDRESS_LH, 127.0.0.2 -> next: uni_1 순환!)
        // 768: pfx_1 (IP_ADAPTER_PREFIX_XP, 127.0.0.0/8 -> next: null)
        // 1024: gw_1 (IP_ADAPTER_GATEWAY_ADDRESS_LH, 127.0.0.254 -> next: gw_1 자기 순환!)
        // 1280: dns_1 (IP_ADAPTER_DNS_SERVER_ADDRESS_XP, ::1 -> next: null)
        // 2048: SOCKADDR_IN (127.0.0.1)
        // 2112: SOCKADDR_IN (127.0.0.2)
        // 2176: SOCKADDR_IN (127.0.0.0)
        // 2240: SOCKADDR_IN (127.0.0.254)
        // 2304: SOCKADDR_IN6 (::1)
        // 3000: AdapterName b"sub0\0"
        // 3100: FriendlyName "SublistLoopback\0" UTF-16
        // SAFETY: 8192 바이트 정렬 버퍼 내부의 비중첩 영역에 테스트용 네이티브 구조체를 직접 구성한다.
        unsafe {
            // 소켓 주소 구성 (모두 로컬 루프백 한정)
            let sin_1_ptr = base_ptr.add(2048).cast::<SOCKADDR_IN>();
            let mut sin_1: SOCKADDR_IN = std::mem::zeroed();
            sin_1.sin_family = AF_INET;
            sin_1.sin_addr.S_un.S_addr = ipv4_to_network_u32(Ipv4Addr::LOCALHOST);
            sin_1_ptr.write_unaligned(sin_1);

            let sin_2_ptr = base_ptr.add(2112).cast::<SOCKADDR_IN>();
            let mut sin_2: SOCKADDR_IN = std::mem::zeroed();
            sin_2.sin_family = AF_INET;
            sin_2.sin_addr.S_un.S_addr = ipv4_to_network_u32(Ipv4Addr::new(127, 0, 0, 2));
            sin_2_ptr.write_unaligned(sin_2);

            let sin_pfx_ptr = base_ptr.add(2176).cast::<SOCKADDR_IN>();
            let mut sin_pfx: SOCKADDR_IN = std::mem::zeroed();
            sin_pfx.sin_family = AF_INET;
            sin_pfx.sin_addr.S_un.S_addr = ipv4_to_network_u32(Ipv4Addr::new(127, 0, 0, 0));
            sin_pfx_ptr.write_unaligned(sin_pfx);

            let sin_gw_ptr = base_ptr.add(2240).cast::<SOCKADDR_IN>();
            let mut sin_gw: SOCKADDR_IN = std::mem::zeroed();
            sin_gw.sin_family = AF_INET;
            sin_gw.sin_addr.S_un.S_addr = ipv4_to_network_u32(Ipv4Addr::new(127, 0, 0, 254));
            sin_gw_ptr.write_unaligned(sin_gw);

            let sin6_dns_ptr = base_ptr.add(2304).cast::<SOCKADDR_IN6>();
            let mut sin6_dns: SOCKADDR_IN6 = std::mem::zeroed();
            sin6_dns.sin6_family = AF_INET6;
            sin6_dns.sin6_addr.u.Byte = Ipv6Addr::LOCALHOST.octets();
            sin6_dns_ptr.write_unaligned(sin6_dns);

            // 문자열 구성
            let name_bytes = b"sub0\0";
            std::ptr::copy_nonoverlapping(
                name_bytes.as_ptr(),
                base_ptr.add(3000),
                name_bytes.len(),
            );

            let friendly_u16: Vec<u16> = "SublistLoopback\0".encode_utf16().collect();
            std::ptr::copy_nonoverlapping(
                friendly_u16.as_ptr(),
                base_ptr.add(3100).cast::<u16>(),
                friendly_u16.len(),
            );

            // 유니캐스트 하위 노드 1 및 2 구성 (상호 순환: uni_1 -> uni_2 -> uni_1)
            let uni_1_ptr = base_ptr.add(512).cast::<IP_ADAPTER_UNICAST_ADDRESS_LH>();
            let uni_2_ptr = base_ptr.add(640).cast::<IP_ADAPTER_UNICAST_ADDRESS_LH>();

            let mut uni_1: IP_ADAPTER_UNICAST_ADDRESS_LH = std::mem::zeroed();
            uni_1.Anonymous.Anonymous.Length =
                std::mem::size_of::<IP_ADAPTER_UNICAST_ADDRESS_LH>() as u32;
            uni_1.Address = SOCKET_ADDRESS {
                lpSockaddr: sin_1_ptr.cast::<SOCKADDR>(),
                iSockaddrLength: std::mem::size_of::<SOCKADDR_IN>() as i32,
            };
            uni_1.OnLinkPrefixLength = 8;
            uni_1.Next = uni_2_ptr;
            uni_1_ptr.write_unaligned(uni_1);

            let mut uni_2: IP_ADAPTER_UNICAST_ADDRESS_LH = std::mem::zeroed();
            uni_2.Anonymous.Anonymous.Length =
                std::mem::size_of::<IP_ADAPTER_UNICAST_ADDRESS_LH>() as u32;
            uni_2.Address = SOCKET_ADDRESS {
                lpSockaddr: sin_2_ptr.cast::<SOCKADDR>(),
                iSockaddrLength: std::mem::size_of::<SOCKADDR_IN>() as i32,
            };
            uni_2.OnLinkPrefixLength = 8;
            // 순환 주입: uni_2 -> uni_1
            uni_2.Next = uni_1_ptr;
            uni_2_ptr.write_unaligned(uni_2);

            // 프리픽스 하위 노드 구성 (정상 비순환)
            let pfx_ptr = base_ptr.add(768).cast::<IP_ADAPTER_PREFIX_XP>();
            let mut pfx: IP_ADAPTER_PREFIX_XP = std::mem::zeroed();
            pfx.Anonymous.Anonymous.Length = std::mem::size_of::<IP_ADAPTER_PREFIX_XP>() as u32;
            pfx.Address = SOCKET_ADDRESS {
                lpSockaddr: sin_pfx_ptr.cast::<SOCKADDR>(),
                iSockaddrLength: std::mem::size_of::<SOCKADDR_IN>() as i32,
            };
            pfx.PrefixLength = 8;
            pfx.Next = std::ptr::null_mut();
            pfx_ptr.write_unaligned(pfx);

            // 게이트웨이 하위 노드 구성 (자기 순환: gw_1 -> gw_1)
            let gw_ptr = base_ptr.add(1024).cast::<IP_ADAPTER_GATEWAY_ADDRESS_LH>();
            let mut gw: IP_ADAPTER_GATEWAY_ADDRESS_LH = std::mem::zeroed();
            gw.Anonymous.Anonymous.Length =
                std::mem::size_of::<IP_ADAPTER_GATEWAY_ADDRESS_LH>() as u32;
            gw.Address = SOCKET_ADDRESS {
                lpSockaddr: sin_gw_ptr.cast::<SOCKADDR>(),
                iSockaddrLength: std::mem::size_of::<SOCKADDR_IN>() as i32,
            };
            // 자기 참조 순환 주입: gw_1 -> gw_1
            gw.Next = gw_ptr;
            gw_ptr.write_unaligned(gw);

            // DNS 하위 노드 구성 (IPv6 루프백 ::1, 정상 비순환)
            let dns_ptr = base_ptr.add(1280).cast::<IP_ADAPTER_DNS_SERVER_ADDRESS_XP>();
            let mut dns: IP_ADAPTER_DNS_SERVER_ADDRESS_XP = std::mem::zeroed();
            dns.Anonymous.Anonymous.Length =
                std::mem::size_of::<IP_ADAPTER_DNS_SERVER_ADDRESS_XP>() as u32;
            dns.Address = SOCKET_ADDRESS {
                lpSockaddr: sin6_dns_ptr.cast::<SOCKADDR>(),
                iSockaddrLength: std::mem::size_of::<SOCKADDR_IN6>() as i32,
            };
            dns.Next = std::ptr::null_mut();
            dns_ptr.write_unaligned(dns);

            // 어댑터 루트 헤더 구성 (단일 어댑터, Next = null)
            let adapter_ptr = base_ptr.cast::<IP_ADAPTER_ADDRESSES_LH>();
            let mut adapter: IP_ADAPTER_ADDRESSES_LH = std::mem::zeroed();
            adapter.Anonymous1.Anonymous.Length =
                std::mem::size_of::<IP_ADAPTER_ADDRESSES_LH>() as u32;
            adapter.Anonymous1.Anonymous.IfIndex = 1;
            adapter.Ipv6IfIndex = 1;
            adapter.AdapterName = base_ptr.add(3000);
            adapter.FriendlyName = base_ptr.add(3100).cast::<u16>();
            adapter.OperStatus = IfOperStatusUp;
            adapter.FirstUnicastAddress = uni_1_ptr;
            adapter.FirstPrefix = pfx_ptr;
            adapter.FirstGatewayAddress = gw_ptr;
            adapter.FirstDnsServerAddress = dns_ptr;
            adapter.Next = std::ptr::null_mut();
            adapter_ptr.write_unaligned(adapter);
        }

        let mut limitations = Vec::new();
        let adapters = parse_adapters_from_aligned_buffer(&buf, total_bytes, &mut limitations);

        // 1. 단일 어댑터 파싱 완료 확인
        assert_eq!(adapters.len(), 1, "어댑터 1개가 정상 반환되어야 합니다");
        let item = &adapters[0];
        assert_eq!(item.interface_index, 1);
        assert_eq!(item.name, "SublistLoopback");
        assert_eq!(item.adapter_name, "sub0");
        assert_eq!(item.operational_status, "UP");

        // 2. 하위 리스트 순환 발생 전 이미 유효하게 파싱된 행의 보존(retention of valid earlier rows) 검증
        assert_eq!(
            item.ips,
            vec!["127.0.0.1".to_string(), "127.0.0.2".to_string()],
            "유니캐스트 순환 전 방문한 127.0.0.1 및 127.0.0.2 행이 모두 보존되어야 합니다"
        );
        assert_eq!(item.unicast_addresses.len(), 2);
        assert_eq!(item.unicast_addresses[0].ip, "127.0.0.1");
        assert_eq!(item.unicast_addresses[1].ip, "127.0.0.2");

        assert_eq!(
            item.prefixes,
            vec!["127.0.0.0/8".to_string()],
            "프리픽스 행이 보존되어야 합니다"
        );
        assert_eq!(
            item.gateways,
            vec!["127.0.0.254".to_string()],
            "게이트웨이 자기 순환 전 방문한 127.0.0.254 행이 보존되어야 합니다"
        );
        assert_eq!(
            item.dns_servers,
            vec!["::1".to_string()],
            "DNS 서버 ::1 행이 정상 보존되어야 합니다"
        );

        // 3. 하위 리스트 순환 감지 부분 마커(partial marker) 검증
        assert!(
            limitations.iter().any(|l| l.contains(ADAPTER_PARTIAL_LIMITATION_PREFIX)
                && l.contains("유니캐스트 주소 하위 목록: 순환 포인터가 감지되어 순회를 중단했습니다")),
            "유니캐스트 하위 목록 순환 포인터 감지 제한사항이 기록되어야 합니다"
        );
        assert!(
            limitations.iter().any(|l| l.contains(ADAPTER_PARTIAL_LIMITATION_PREFIX)
                && l.contains("게이트웨이 하위 목록: 순환 포인터가 감지되어 순회를 중단했습니다")),
            "게이트웨이 하위 목록 순환 포인터 감지 제한사항이 기록되어야 합니다"
        );

        // 4. 부분 수집 오류 승격 검증 (완전한 성공으로 위장 방지)
        let errors = adapter_partial_errors(&limitations);
        assert_eq!(errors.len(), 1, "부분 수집 오류가 1건으로 요약 생성되어야 합니다");
        assert!(errors[0].contains("2건"));
        assert!(errors[0].contains("부분적으로만 수집"));

        // 5. 스냅샷 조립 시 파싱된 어댑터 행 보존 및 errors 동시 유지 확인
        let snapshot = build_host_snapshot_from_parts(
            Some(adapters),
            Some(Vec::new()),
            None,
            errors,
            limitations,
        );
        assert_eq!(
            snapshot.adapters.as_array().map(|a| a.len()),
            Some(1),
            "스냅샷에 부분 수집된 어댑터 행이 보존되어야 합니다"
        );
        assert_eq!(
            snapshot.errors.len(),
            1,
            "스냅샷 errors에 부분 수집 오류가 기록되어야 합니다"
        );
    }
}

#[test]
#[ignore = "실제 네이티브 호스트 스냅샷 검증: 부모 명시 실행"]
fn native_collect_host_snapshot_ipv4_loopback() {
    let snapshot = collect_host_snapshot(IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert!(snapshot.errors.is_empty(), "루프백 스냅샷 오류 없어야 함");

    let adapters = snapshot
        .adapters
        .as_array()
        .expect("adapters는 JSON 배열이어야 합니다");
    assert!(
        !adapters.is_empty(),
        "최소 1개 이상의 어댑터가 존재해야 합니다"
    );

    let routes = snapshot
        .routes
        .as_array()
        .expect("routes는 JSON 배열이어야 합니다");
    assert!(
        !routes.is_empty(),
        "최소 1개 이상의 라우트가 존재해야 합니다"
    );

    let selected = snapshot
        .selected_route
        .as_object()
        .expect("selected_route는 JSON 객체여야 합니다");
    assert_eq!(
        selected.get("source_ip").and_then(Value::as_str),
        Some("127.0.0.1")
    );
    assert!(
        selected
            .get("interface_index")
            .and_then(Value::as_u64)
            .is_some()
    );
    assert_eq!(
        selected
            .get("remote_connectivity_evidence")
            .and_then(Value::as_bool),
        Some(false)
    );
}

#[test]
#[ignore = "실제 네이티브 호스트 스냅샷 검증: 부모 명시 실행"]
fn native_collect_host_snapshot_ipv6_loopback() {
    let snapshot = collect_host_snapshot(IpAddr::V6(Ipv6Addr::LOCALHOST));
    assert!(
        snapshot.errors.is_empty(),
        "IPv6 루프백 스냅샷 오류 없어야 함"
    );
    assert!(snapshot.adapters.is_array());
    assert!(snapshot.routes.is_array());

    let selected = snapshot
        .selected_route
        .as_object()
        .expect("selected_route는 JSON 객체여야 합니다");
    assert_eq!(
        selected.get("source_ip").and_then(Value::as_str),
        Some("::1")
    );
    assert_eq!(
        selected
            .get("remote_connectivity_evidence")
            .and_then(Value::as_bool),
        Some(false)
    );
}
