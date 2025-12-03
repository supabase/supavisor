defmodule Supavisor.Support.SSLHelper do
  @moduledoc """
  Helper module to generate self-signed SSL certificates for testing.
  """

  @doc """
  Generates a self-signed certificate and key for testing.
  Returns {:ok, cert_path, key_path} or {:error, reason}.
  """
  def setup_test_ssl_certificates do
    test_dir = Path.join([System.tmp_dir!(), "supavisor_test_ssl"])
    File.mkdir_p!(test_dir)

    cert_path = Path.join(test_dir, "test_cert.pem")
    key_path = Path.join(test_dir, "test_key.pem")

    # Check if certificates already exist
    if File.exists?(cert_path) and File.exists?(key_path) do
      {:ok, cert_path, key_path}
    else
      # Generate self-signed certificate using openssl
      case System.cmd("openssl", [
             "req",
             "-x509",
             "-newkey",
             "rsa:2048",
             "-keyout",
             key_path,
             "-out",
             cert_path,
             "-days",
             "365",
             "-nodes",
             "-subj",
             "/CN=localhost"
           ]) do
        {_, 0} ->
          {:ok, cert_path, key_path}

        {output, code} ->
          {:error, "Failed to generate SSL certificates: #{output} (exit code: #{code})"}
      end
    end
  end

  @doc """
  Configures the application to use test SSL certificates.
  """
  def configure_test_ssl do
    case setup_test_ssl_certificates() do
      {:ok, cert_path, key_path} ->
        Application.put_env(:supavisor, :global_downstream_cert, cert_path)
        Application.put_env(:supavisor, :global_downstream_key, key_path)
        {:ok, cert_path, key_path}

      error ->
        error
    end
  end

  @doc """
  Cleans up test SSL certificates.
  """
  def cleanup_test_ssl do
    test_dir = Path.join([System.tmp_dir!(), "supavisor_test_ssl"])
    File.rm_rf(test_dir)
  end
end
