/* SPDX-License-Identifier: AGPL-3.0-only */
/* Only compiled for constant generation, never loaded into the kernel.
 * Typed globals retain every enum in BTF, including purely numeric layouts.
 */
#include "routing_abi.h"

enum routing_limits export_routing_limits;
enum outbound_index export_outbound_index;
enum outbound_connectivity_state export_outbound_connectivity_state;
enum capture_flags export_capture_flags;
enum route_result_bits export_route_result_bits;
enum match_flags export_match_flags;
enum MatchType export_MatchType;
enum MatchAction export_MatchAction;
enum L4ProtoType export_L4ProtoType;
enum IpVersionType export_IpVersionType;
enum http_client_kind export_http_client_kind;
enum http_client_layout export_http_client_layout;
enum api_client_link_type export_api_client_link_type;
enum handoff_constants export_handoff_constants;
