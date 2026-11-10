defmodule Supavisor.TLSHandshake do
  @moduledoc """
  `:ssl.handshake/3` for an accepted `:gen_tcp` socket, but with each connection's process tree
  started under a partitioned supervisor instead of ssl's single `tls_connection_sup`.

  Every handshake makes a synchronous `start_child` on that supervisor, which returns only after
  the new child has been scheduled and acked. When the schedulers are saturated each start waits
  in the run queue, so one supervisor caps the handshake rate below the arrival rate and its
  mailbox grows until the node stops accepting TLS connections.

  Ported from ssl 11.2.12.11 (OTP 27.3.4), and relies on ssl internals, so it must be rechecked
  on every OTP upgrade. Each function names the one it ports, and the code follows the source,
  except for:

    * `start_dyn_connection_sup/1`, which starts non-distribution connections under a partition
      of `#{inspect(__MODULE__)}.Supervisor` instead of `tls_connection_sup`.
    * Option processing. `ssl:handshake/3` processes the options on every call, with ssl's
      private `handle_options/5`, which we would need to inline/copy a lot of ssl internal code
      to port. Instead, `handle_options/1` processes them once, ahead of time, with the public
      `ssl:handle_options/3`, which runs the same processing without a socket. `handshake/3`
      takes the result and merges the socket's emulated options (which `/5` does). It doesn't
      do the check that a certificate or an anonymous cipher suite is configured, and when the
      options have no `log_level`, ssl's logger level is read once, by `handle_options/1`.
    * `handshake/6`, which calls this module's `start_fsm/8` instead of the connection module
      from `connection_cb/1`, so that isn't ported.
  """

  require Record

  Record.defrecordp(:config, Record.extract(:config, from_lib: "ssl/src/ssl_internal.hrl"))

  Record.defrecordp(
    :socket_options,
    Record.extract(:socket_options, from_lib: "ssl/src/ssl_internal.hrl")
  )

  @sup __MODULE__.Supervisor

  # tls_connection_sup's child spec.
  @dyn_sup_spec %{
    id: :tls_dyn_connection_sup,
    start: {:tls_dyn_connection_sup, :start_link, []},
    restart: :temporary,
    type: :supervisor,
    shutdown: :infinity
  }

  def child_spec(_) do
    PartitionSupervisor.child_spec(child_spec: DynamicSupervisor, name: @sup)
  end

  @typedoc "Server options processed by `handle_options/1`."
  @type options :: record(:config)

  @doc """
  Processes server options for `handshake/3`, which `:ssl.handshake/3` does on every call.
  Throws `{:error, reason}` for invalid options.
  """
  @spec handle_options([:ssl.tls_server_option()]) :: options()
  def handle_options(ssl_options) do
    {:ok, config} = :ssl.handle_options(ssl_options, :server, :undefined)
    config
  end

  # Port of ssl:handshake/3, the clause for a socket that isn't an #sslsocket{}, with the options
  # processed by handle_options/1.
  @spec handshake(:gen_tcp.socket(), options(), timeout()) ::
          {:ok, :ssl.sslsocket()} | {:ok, :ssl.sslsocket(), map()} | {:error, term()}
  def handshake(
        socket,
        config(transport_info: cb_info, ssl: ssl_opts, emulated: emulated0),
        timeout
      )
      when (is_integer(timeout) and timeout >= 0) or timeout == :infinity do
    transport = elem(cb_info, 0)
    em_opts = emulated_options(transport, socket, emulated0)
    :ok = :tls_socket.setopts(transport, socket, :tls_socket.internal_inet_values())
    {:ok, port} = :tls_socket.port(transport, socket)
    {:ok, session_id_handle} = :tls_socket.session_id_tracker(:ssl_unknown_listener, ssl_opts)

    handshake(
      port,
      socket,
      {ssl_opts, :tls_socket.emulated_socket_options(em_opts, socket_options()),
       [{:session_id_tracker, session_id_handle}]},
      self(),
      cb_info,
      timeout
    )
  catch
    {:error, _reason} = error -> error
  end

  # Port of ssl:emulated_options/4, given the options it computes with a socket of undefined,
  # which ssl:handle_options/3 has already computed.
  defp emulated_options(transport, socket, emulated0) do
    emulated_options = :tls_socket.emulated_options()
    {:ok, original} = :tls_socket.getopts(transport, socket, emulated_options)
    :lists.ukeymerge(1, emulated0, original)
  end

  # Port of ssl_gen_statem:handshake/7.
  defp handshake(port, socket, opts, user, cb_info, timeout) do
    start_fsm(:server, ~c"localhost", port, socket, opts, user, cb_info, timeout)
  catch
    :exit, {:noproc, _} -> {:error, :ssl_not_started}
  end

  # Port of tls_gen_connection:start_fsm/8.
  defp start_fsm(
         role,
         host,
         port,
         socket,
         {ssl_opts, _, trackers} = opts,
         user,
         {cb_module, _, _, _, _} = cb_info,
         timeout
       ) do
    erl_dist = Map.get(ssl_opts, :erl_dist, false)
    sender_spawn_opts = Map.get(ssl_opts, :sender_spawn_opts, [])
    sender_options = handle_sender_options(erl_dist, sender_spawn_opts)

    starter =
      start_connection_tree(user, erl_dist, sender_options, role, [
        host,
        port,
        socket,
        opts,
        user,
        cb_info
      ])

    receive do
      {^starter, sock_receiver, sock_sender} ->
        socket_control(socket, sock_receiver, sock_sender, cb_module, trackers, timeout)

      {^starter, error} ->
        error
    end
  end

  # Port of tls_gen_connection:handle_sender_options/2.
  defp handle_sender_options(erl_dist, spawn_opts) do
    case erl_dist do
      true ->
        [[{:spawn_opt, [{:priority, :max} | :proplists.delete(:priority, spawn_opts)]}]]

      false ->
        [[{:spawn_opt, spawn_opts}]]
    end
  end

  # Port of tls_gen_connection:start_connection_tree/5.
  defp start_connection_tree(user, is_erl_dist, sender_opts, role, receiver_opts) do
    start_connection_tree = fn ->
      try do
        start_dyn_connection_sup(is_erl_dist)
      catch
        :exit, {:noproc, _} ->
          send(user, {self(), {:error, :ssl_not_started}})

        _, reason ->
          # SSL_LOG(notice, internal_error, ...) in a process without a log_level.
          :ssl_logger.log(
            :notice,
            :debug,
            %{description: :internal_error, reason: [error: reason, stacktrace: __STACKTRACE__]},
            %{
              mfa: {__MODULE__, :start_connection_tree, 5},
              line: __ENV__.line,
              file: String.to_charlist(__ENV__.file)
            }
          )

          send(user, {self(), {:error, :internal_error}})
      else
        {:ok, dyn_sup} ->
          case :tls_dyn_connection_sup.start_child(dyn_sup, :sender, sender_opts) do
            {:ok, sender} ->
              case :tls_dyn_connection_sup.start_child(dyn_sup, :receiver, [
                     role,
                     sender | receiver_opts
                   ]) do
                {:ok, receiver} ->
                  send(user, {self(), receiver, sender})

                {:error, error} ->
                  send(user, {self(), error})
                  Process.exit(dyn_sup, :shutdown)
              end

            {:error, error} ->
              send(user, {self(), error})
              Process.exit(dyn_sup, :shutdown)
          end

        {:error, error} ->
          send(user, {self(), error})
      end
    end

    spawn(start_connection_tree)
  end

  # Port of tls_gen_connection:start_dyn_connection_sup/1, with non-distribution connections
  # started under a partition of this module's supervisor instead of tls_connection_sup.
  defp start_dyn_connection_sup(true), do: :tls_connection_sup.start_child_dist([])

  defp start_dyn_connection_sup(false) do
    DynamicSupervisor.start_child({:via, PartitionSupervisor, {@sup, self()}}, @dyn_sup_spec)
  end

  # Port of tls_gen_connection:socket_control/6.
  defp socket_control(socket, sock_receiver, sock_sender, cb_module, trackers, timeout) do
    case :ssl_gen_statem.socket_control(
           :tls_gen_connection,
           socket,
           [sock_receiver, sock_sender],
           cb_module,
           trackers
         ) do
      {:ok, ssl_socket} -> :ssl_gen_statem.handshake(ssl_socket, timeout)
      error -> error
    end
  end
end
