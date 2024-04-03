alias Supavisor.Helpers, as: H

map = %{:a => 1, "key" => "value", "ключ" => "значення"}
text = "big_secret"
map_enc = <<1, 10, 65, 69, 83, 46, 71, 67, 77, 46, 86, 49, 187, 130, 166, 189, 94, 38, 109, 83, 9, 109, 228, 202, 104, 33, 49, 31, 105, 142, 219, 106, 114, 21, 167, 60, 192, 204, 56, 9, 111, 223, 208, 47, 247, 74, 178, 192, 209, 153, 54, 23, 150, 155, 82, 180, 188, 2, 87, 189, 180, 225, 66, 243, 111, 73, 73, 199, 2, 240, 51, 227, 168, 202, 197, 247, 210, 197, 100, 67, 230, 32, 175, 110, 173, 21, 219, 110, 244, 166, 79, 70, 200, 75, 206, 222, 116, 177, 243, 239, 141, 80, 6, 33, 250, 188, 92, 73>>
text_enc = <<1, 10, 65, 69, 83, 46, 71, 67, 77, 46, 86, 49, 79, 49, 25, 197, 18, 255, 27, 3, 45, 198, 65, 15, 230, 155, 246, 84, 13, 125, 122, 178, 51, 203, 103, 149, 86, 117, 61, 106, 220, 97, 155, 204, 118, 20, 217, 71, 15, 250, 43, 171, 6, 68, 250, 58, 215, 45, 0, 60>>

Benchee.run(%{
  "encode_secret map" => fn ->
    H.encode_secret(map)
  end,
  "encode_secret text" => fn ->
    H.encode_secret(text)
  end,
  "decode_secret map" => fn ->
    H.decode_secret(map_enc)
  end,
  "decode_secret text" => fn ->
    H.decode_secret(text_enc)
  end
})


# $ VAULT_ENC_KEY="aHD8DZRdk2emnkdktFZRh3E9RNg4aOY7" mix run bench/enc_dec.exs

# Operating System: macOS
# CPU Information: Apple M1 Pro
# Number of Available Cores: 10
# Available memory: 16 GB
# Elixir 1.14.3
# Erlang 24.3.4

# Benchmark suite executing with the following configuration:
# warmup: 2 s
# time: 5 s
# memory time: 0 ns
# reduction time: 0 ns
# parallel: 1
# inputs: none specified
# Estimated total run time: 28 s

# Benchmarking decode_secret map ...
# Benchmarking decode_secret text ...
# Benchmarking encode_secret map ...
# Benchmarking encode_secret text ...

# Name                         ips        average  deviation         median         99th %
# decode_secret text      753.68 K        1.33 μs  ±1293.76%        1.25 μs        1.50 μs
# encode_secret text      708.57 K        1.41 μs   ±453.06%        1.33 μs        1.88 μs
# decode_secret map       692.11 K        1.44 μs   ±945.34%        1.33 μs        1.67 μs
# encode_secret map       671.23 K        1.49 μs   ±414.54%        1.42 μs        1.96 μs

# Comparison:
# decode_secret text      753.68 K
# encode_secret text      708.57 K - 1.06x slower +0.0845 μs
# decode_secret map       692.11 K - 1.09x slower +0.118 μs
# encode_secret map       671.23 K - 1.12x slower +0.163 μs
