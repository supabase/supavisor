defmodule Supavisor.Integration.SSLCertNegotiationTest do
  use Supavisor.DataCase, async: false

  require Supavisor.Protocol.Server

  @certs_dir Path.expand("../../priv/test/certs", __DIR__)

  @rsa_ciphers [
    {:dhe_rsa, :aes_256_gcm, :aead, :sha384},
    {:dhe_rsa, :aes_128_gcm, :aead, :sha256},
    {:ecdhe_rsa, :aes_256_gcm, :aead, :sha384},
    {:ecdhe_rsa, :aes_128_gcm, :aead, :sha256}
  ]

  @ecdsa_ciphers [
    {:ecdhe_ecdsa, :aes_256_gcm, :aead, :sha384},
    {:ecdhe_ecdsa, :aes_128_gcm, :aead, :sha256}
  ]

  setup_all do
    Supavisor.Support.SSLHelper.setup_downstream_certs()
    Supavisor.Support.SSLHelper.setup_downstream_v2_certs(["v2.localhost"])
  end

  describe "TLS 1.2" do
    test "negotiates RSA certificate when client requests RSA-only ciphers" do
      {:ok, ssl_socket} = connect_with_ciphers(:rsa)
      assert peer_cert_algorithm(ssl_socket) == :rsa
    end

    test "negotiates ECDSA certificate when client requests ECDSA-only ciphers" do
      {:ok, ssl_socket} = connect_with_ciphers(:ecdsa)
      assert peer_cert_algorithm(ssl_socket) == :ec
    end

    test "RSA certificate passes CA verification" do
      {:ok, ssl_socket} = connect_with_verify_peer(:rsa)
      assert peer_cert_algorithm(ssl_socket) == :rsa
    end

    test "ECDSA certificate passes CA verification" do
      {:ok, ssl_socket} = connect_with_verify_peer(:ecdsa)
      assert peer_cert_algorithm(ssl_socket) == :ec
    end

    test "defaults to ECDSA certificate" do
      {:ok, ssl_socket} = ssl_upgrade(versions: [:"tlsv1.2"], verify: :verify_none)
      assert peer_cert_algorithm(ssl_socket) == :ec
    end
  end

  describe "TLS 1.3" do
    test "negotiates ECDSA certificate" do
      {:ok, ssl_socket} =
        ssl_upgrade(versions: [:"tlsv1.3"], verify: :verify_none)

      assert peer_cert_algorithm(ssl_socket) == :ec
    end

    test "ECDSA certificate passes CA verification" do
      {:ok, ssl_socket} =
        ssl_upgrade(
          versions: [:"tlsv1.3"],
          verify: :verify_peer,
          cacerts: [ca_der()],
          server_name_indication: ~c"localhost"
        )

      assert peer_cert_algorithm(ssl_socket) == :ec
    end
  end

  describe "SNI hostname" do
    test "serves v2 certificate to a configured hostname" do
      {:ok, ssl_socket} =
        ssl_upgrade(verify: :verify_none, server_name_indication: ~c"v2.localhost")

      assert :ssl.peercert(ssl_socket) == {:ok, cert_der("server_v2_ecdsa.crt")}
    end

    test "matches hostnames case-insensitively" do
      {:ok, ssl_socket} =
        ssl_upgrade(verify: :verify_none, server_name_indication: ~c"V2.LOCALHOST")

      assert :ssl.peercert(ssl_socket) == {:ok, cert_der("server_v2_ecdsa.crt")}
    end

    test "serves v2 RSA certificate when client requests RSA-only ciphers" do
      {:ok, ssl_socket} =
        ssl_upgrade(
          versions: [:"tlsv1.2"],
          ciphers: @rsa_ciphers,
          verify: :verify_none,
          server_name_indication: ~c"v2.localhost"
        )

      assert :ssl.peercert(ssl_socket) == {:ok, cert_der("server_v2_rsa.crt")}
    end

    test "v2 certificate passes v2 CA verification" do
      {:ok, ssl_socket} =
        ssl_upgrade(
          verify: :verify_peer,
          cacerts: [cert_der("ca_v2.crt")],
          server_name_indication: ~c"v2.localhost"
        )

      assert :ssl.peercert(ssl_socket) == {:ok, cert_der("server_v2_ecdsa.crt")}
    end

    test "serves default certificate to other hostnames" do
      {:ok, ssl_socket} = ssl_upgrade(verify: :verify_none, server_name_indication: ~c"localhost")
      assert :ssl.peercert(ssl_socket) == {:ok, cert_der("server_ecdsa.crt")}
    end

    test "serves default certificate to a subdomain of a configured hostname" do
      {:ok, ssl_socket} =
        ssl_upgrade(verify: :verify_none, server_name_indication: ~c"tenant.v2.localhost")

      assert :ssl.peercert(ssl_socket) == {:ok, cert_der("server_ecdsa.crt")}
    end

    test "serves default certificate without SNI" do
      {:ok, ssl_socket} = ssl_upgrade(verify: :verify_none)
      assert :ssl.peercert(ssl_socket) == {:ok, cert_der("server_ecdsa.crt")}
    end

    test "serves default certificate when v2 certificates are not configured" do
      for key <- [
            :downstream_v2_cert,
            :downstream_v2_key,
            :downstream_v2_ec_cert,
            :downstream_v2_ec_key
          ] do
        value = Application.get_env(:supavisor, key)
        Application.delete_env(:supavisor, key)
        on_exit(fn -> Application.put_env(:supavisor, key, value) end)
      end

      {:ok, ssl_socket} =
        ssl_upgrade(verify: :verify_none, server_name_indication: ~c"v2.localhost")

      assert :ssl.peercert(ssl_socket) == {:ok, cert_der("server_ecdsa.crt")}
    end
  end

  defp connect_with_ciphers(type) do
    ciphers = if type == :rsa, do: @rsa_ciphers, else: @ecdsa_ciphers

    ssl_upgrade(
      versions: [:"tlsv1.2"],
      ciphers: ciphers,
      verify: :verify_none
    )
  end

  defp connect_with_verify_peer(type) do
    ciphers = if type == :rsa, do: @rsa_ciphers, else: @ecdsa_ciphers

    ssl_upgrade(
      versions: [:"tlsv1.2"],
      ciphers: ciphers,
      verify: :verify_peer,
      cacerts: [ca_der()],
      server_name_indication: ~c"localhost"
    )
  end

  defp ssl_upgrade(ssl_opts) do
    port = Application.get_env(:supavisor, :proxy_port_transaction)
    {:ok, tcp} = :gen_tcp.connect(~c"localhost", port, [:binary, active: false])
    :ok = :gen_tcp.send(tcp, Supavisor.Protocol.Server.ssl_request_message())
    {:ok, "S"} = :gen_tcp.recv(tcp, 1, 5_000)
    :ssl.connect(tcp, ssl_opts, 5_000)
  end

  defp ca_der, do: cert_der("ca.crt")

  defp cert_der(file) do
    pem = File.read!(Path.join(@certs_dir, file))
    [{:Certificate, der, :not_encrypted}] = :public_key.pem_decode(pem)
    der
  end

  defp peer_cert_algorithm(ssl_socket) do
    {:ok, der} = :ssl.peercert(ssl_socket)
    cert = :public_key.pkix_decode_cert(der, :otp)
    {:OTPSubjectPublicKeyInfo, {:PublicKeyAlgorithm, algo_oid, _}, _} = elem(elem(cert, 1), 7)

    case algo_oid do
      # 1.2     = ISO/ITU-T
      # 840     = USA (ANSI)
      # 113549  = RSA Security / PKCS
      # 1.1.1   = rsaEncryption
      {1, 2, 840, 113_549, 1, 1, 1} -> :rsa
      # 1.2     = ISO/ITU-T
      # 840     = USA (ANSI)
      # 10045   = ANSI X9.62 (elliptic curve standard)
      # 2.1     = id-ecPublicKey
      {1, 2, 840, 10_045, 2, 1} -> :ec
    end
  end
end
