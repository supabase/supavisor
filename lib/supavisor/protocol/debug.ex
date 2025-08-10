defmodule Supavisor.Protocol.Debug do
  @moduledoc """
  Debugging utilities for PostgreSQL protocol messages.
  """

  @spec packet_to_string(binary() | tuple() | struct(), :frontend | :backend) :: String.t()
  def packet_to_string(packet, source) do
    case packet do
      {:bind_pkt, stmt_name, _pkt, _parse_pkt} ->
        "BindMessage(statement=#{inspect(stmt_name)})"

      {:close_pkt, stmt_name, _pkt} ->
        "CloseMessage(statement=#{inspect(stmt_name)})"

      {:describe_pkt, stmt_name, _pkt} ->
        "DescribeMessage(statement=#{inspect(stmt_name)})"

      {:parse_pkt, stmt_name, _pkt} ->
        "ParseMessage(statement=#{inspect(stmt_name)})"

      %{bin: bin} when is_binary(bin) ->
        packet_to_string(bin, source)

      bin when is_binary(bin) ->
        {packets, remaining} = Supavisor.Protocol.split_pkts(bin)

        packets_str = Enum.map_join(packets, ", ", &format_raw_binary(&1, source))

        case {packets_str, remaining} do
          {"", ""} -> format_raw_binary(bin, source)
          {"", _} -> "Incomplete(#{inspect(remaining)})"
          {str, ""} -> str
          {str, _} -> str <> ", Incomplete(#{inspect(remaining)})"
        end

      other ->
        "UnknownPacket(#{inspect(other)})"
    end
  end

  defp format_raw_binary(<<tag, _length::32, rest::binary>>, source),
    do: format_message_by_tag(tag, source, rest)

  defp format_raw_binary(<<tag, rest::binary>>, source),
    do: format_message_by_tag(tag, source, rest)

  defp format_raw_binary(other, _source),
    do: "UnknownPacket(#{inspect(other)})"

  @spec inspect_packet(binary() | tuple() | struct(), :frontend | :backend, String.t() | nil) ::
          binary() | tuple() | struct()
  def inspect_packet(packet, source, label \\ nil) do
    packet_str = packet_to_string(packet, source)
    output = if label, do: "#{label}: #{packet_str}", else: packet_str
    IO.puts(output)
    packet
  end

  defp format_message_by_tag(tag, :frontend, data) do
    case tag do
      ?B -> format_bind_message(data)
      ?C -> format_close_message(data)
      ?D -> format_describe_message(data)
      ?E -> format_execute_message(data)
      ?F -> format_function_call(data)
      ?H -> "Flush"
      ?P -> format_parse_message(data)
      ?Q -> format_query_message(data)
      ?S -> "Sync"
      ?X -> "Terminate"
      ?p -> "Password/SASL/GSS"
      _ -> "UnknownPacket(tag=#{inspect(<<tag>>)}, source=frontend)"
    end
  end

  defp format_message_by_tag(tag, :backend, data) do
    case tag do
      ?1 -> "ParseComplete"
      ?2 -> "BindComplete"
      ?3 -> "CloseComplete"
      ?A -> format_notification_response(data)
      ?C -> format_command_complete(data)
      ?D -> "DataRow"
      ?E -> format_error_response(data)
      ?G -> "CopyInResponse"
      ?H -> "CopyOutResponse"
      ?I -> "EmptyQueryResponse"
      ?K -> "BackendKeyData"
      ?N -> "NoticeResponse"
      ?R -> format_authentication_message(data)
      ?S -> format_parameter_status(data)
      ?T -> "RowDescription"
      ?V -> "FunctionCallResponse"
      ?Z -> format_ready_for_query_message(data)
      ?c -> "CopyDone"
      ?d -> "CopyData"
      ?n -> "NoData"
      ?s -> "PortalSuspended"
      ?t -> "ParameterDescription"
      ?v -> "NegotiateProtocolVersion"
      _ -> "UnknownPacket(tag=#{inspect(<<tag>>)}, source=backend)"
    end
  end

  defp format_authentication_message(<<auth_type::32, _rest::binary>>) do
    case auth_type do
      0 -> "AuthenticationOk"
      2 -> "AuthenticationKerberosV5"
      3 -> "AuthenticationCleartextPassword"
      5 -> "AuthenticationMD5Password"
      6 -> "AuthenticationSCMCredential"
      7 -> "AuthenticationGSS"
      8 -> "AuthenticationGSSContinue"
      9 -> "AuthenticationSSPI"
      10 -> "AuthenticationSASL"
      11 -> "AuthenticationSASLContinue"
      12 -> "AuthenticationSASLFinal"
      _ -> "AuthenticationUnknown(#{auth_type})"
    end
  end

  defp format_authentication_message(_), do: "AuthenticationMalformed"

  defp format_ready_for_query_message(<<status>>) do
    case status do
      ?I -> "ReadyForQuery(idle)"
      ?T -> "ReadyForQuery(transaction_block)"
      ?E -> "ReadyForQuery(failed_transaction_block)"
      _ -> "ReadyForQuery(unknown(#{inspect(<<status>>)}))"
    end
  end

  defp format_ready_for_query_message(_), do: "ReadyForQuery(malformed)"

  defp format_bind_message(data) do
    case extract_null_terminated_string(data) do
      {portal_name, rest} ->
        case extract_null_terminated_string(rest) do
          {stmt_name, _} ->
            "Bind(portal=#{inspect(portal_name)}, statement=#{inspect(stmt_name)})"

          _ ->
            "Bind(malformed)"
        end

      _ ->
        "Bind(malformed)"
    end
  end

  defp format_close_message(data) do
    case data do
      <<type, rest::binary>> ->
        case extract_null_terminated_string(rest) do
          {name, _} ->
            type_str = if type == ?S, do: "statement", else: "portal"
            "Close(#{type_str}=#{inspect(name)})"

          _ ->
            "Close(malformed)"
        end

      _ ->
        "Close(malformed)"
    end
  end

  defp format_describe_message(data) do
    case data do
      <<type, rest::binary>> ->
        case extract_null_terminated_string(rest) do
          {name, _} ->
            type_str = if type == ?S, do: "statement", else: "portal"
            "Describe(#{type_str}=#{inspect(name)})"

          _ ->
            "Describe(malformed)"
        end

      _ ->
        "Describe(malformed)"
    end
  end

  defp format_execute_message(data) do
    case extract_null_terminated_string(data) do
      {portal_name, _} -> "Execute(portal=#{inspect(portal_name)})"
      _ -> "Execute(malformed)"
    end
  end

  defp format_parse_message(data) do
    case extract_null_terminated_string(data) do
      {stmt_name, _} -> "Parse(statement=#{inspect(stmt_name)})"
      _ -> "Parse(malformed)"
    end
  end

  defp format_query_message(data) do
    case extract_null_terminated_string(data) do
      {query, _} ->
        truncated_query = truncate_sql(query)
        "Query(#{truncated_query})"

      _ ->
        "Query(malformed)"
    end
  end

  defp format_function_call(data) do
    case data do
      <<_oid::32, rest::binary>> ->
        case extract_null_terminated_string(rest) do
          {function_name, _} -> "FunctionCall(#{function_name})"
          _ -> "FunctionCall"
        end

      _ ->
        "FunctionCall"
    end
  end

  defp format_command_complete(data) do
    case extract_null_terminated_string(data) do
      {tag, _} -> "CommandComplete(#{inspect(tag)})"
      _ -> "CommandComplete(malformed)"
    end
  end

  defp format_error_response(data) do
    case extract_error_fields(data) do
      %{"M" => message} -> "ErrorResponse(#{inspect(message)})"
      _ -> "ErrorResponse(malformed)"
    end
  end

  defp format_parameter_status(data) do
    case extract_null_terminated_string(data) do
      {name, rest} ->
        case extract_null_terminated_string(rest) do
          {value, _} -> "ParameterStatus(#{name}=\"#{value}\")"
          _ -> "ParameterStatus(malformed)"
        end

      _ ->
        "ParameterStatus(malformed)"
    end
  end

  defp format_notification_response(data) do
    case data do
      <<_pid::32, rest::binary>> ->
        case extract_null_terminated_string(rest) do
          {channel, rest2} ->
            case extract_null_terminated_string(rest2) do
              {payload, _} -> "NotificationResponse(#{channel}, #{inspect(payload)})"
              _ -> "NotificationResponse(#{channel})"
            end

          _ ->
            "NotificationResponse(malformed)"
        end

      _ ->
        "NotificationResponse(malformed)"
    end
  end

  defp extract_error_fields(data) do
    extract_error_fields(data, %{})
  end

  defp extract_error_fields(<<0>>, acc), do: acc

  defp extract_error_fields(<<field_type, rest::binary>>, acc) do
    case extract_null_terminated_string(rest) do
      {value, rest2} ->
        extract_error_fields(rest2, Map.put(acc, <<field_type>>, value))

      _ ->
        acc
    end
  end

  defp extract_error_fields(_, acc), do: acc

  defp truncate_sql(sql) when byte_size(sql) <= 50, do: inspect(sql)

  defp truncate_sql(sql) do
    <<truncated::binary-size(47), _::binary>> = sql
    inspect(truncated <> "...")
  end

  defp extract_null_terminated_string(binary) do
    case :binary.split(binary, <<0>>) do
      [string, rest] -> {string, rest}
      [_] -> nil
    end
  end
end
