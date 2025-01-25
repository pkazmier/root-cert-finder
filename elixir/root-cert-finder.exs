#!/usr/bin/env elixir

# Script that reads a list of domain names and identifies the issuer of the
# root certificate used to sign the domain's certificate. I used this quick
# script to identify how many of the top 10,000 domains used Entrust as their
# root CA given that Google will no longer be trusting Entrust after 2024.
#
#    $ elixir root-cert-finder.exs < list_of_domains.txt

Mix.install([
  {:easy_ssl, git: "https://github.com/pkazmier/EasySSL", branch: "otp-cert-support"}
])

:ssl.start()

defmodule Main do
  @task_timeout 10_000
  @socket_connect_timeout 4_500

  def run do
    logger = spawn(fn -> CertLogger.loop(%{}) end)

    IO.stream(:line)
    |> Stream.map(&String.trim/1)
    |> Task.async_stream(&get_root(&1, logger),
      max_concurrency: 100,
      timeout: @task_timeout,
      on_timeout: :kill_task
    )
    |> Enum.each(fn
      {:ok, _} -> :ok
      {:exit, reason} -> IO.puts(:stderr, "task exited: #{reason}")
    end)

    send(logger, {self(), :stats})

    receive do
      {:ok, counts} ->
        counts
        |> Enum.into([])
        |> List.keysort(1, :desc)
        |> Enum.take(30)
        |> Enum.each(fn {root, count} -> IO.puts("#{count}  #{root}") end)
    end
  end

  def get_root(domain, logger) do
    ssl_opts = [
      cacerts: :public_key.cacerts_get(),
      verify_fun: {&process_cert/3, {0, domain, logger}},
      customize_hostname_check: [match_fun: :public_key.pkix_verify_hostname_match_fun(:https)],
      log_level: :critical
    ]

    domain
    |> String.to_charlist()
    |> :ssl.connect(443, ssl_opts, @socket_connect_timeout)
    |> then(fn
      {:ok, socket} ->
        :ssl.close(socket)

      {:error, reason} when reason == :nxdomain or reason == :timeout ->
        case String.starts_with?(domain, "www.") do
          true -> send(logger, {:error, domain, reason})
          false -> get_root("www." <> to_string(domain), logger)
        end

      {:error, reason} ->
        send(logger, {:error, domain, reason})
    end)
  end

  def process_cert(cert, event, {cert_idx, domain, logger} = state) do
    case event do
      {:bad_cert, _} = reason ->
        {:fail, reason}

      {:extension, _} ->
        {:unknown, state}

      :valid ->
        cert = EasySSL.parse_otp(cert)

        if cert_idx == 0 do
          cn = cert.issuer[:CN] || cert.issuer.aggregated
          send(logger, {:add, domain, cn})
        end

        {:valid, {cert_idx + 1, domain, logger}}

      :valid_peer ->
        {:valid, {cert_idx + 1, domain, logger}}
    end
  end
end

defmodule CertLogger do
  def loop(map) do
    receive do
      {:add, domain, root} ->
        IO.puts(:stderr, "#{domain} --> #{root}")
        map = Map.update(map, root, [domain], fn domains -> [domain | domains] end)
        loop(map)

      {:error, domain, reason} ->
        reason = inspect(reason)
        IO.puts(:stderr, "#{domain} --> ERROR: #{reason}")
        map = Map.update(map, reason, [domain], fn domains -> [domain | domains] end)
        loop(map)

      {from, :stats} ->
        counts = Map.new(map, fn {k, v} -> {k, Enum.count(v)} end)
        send(from, {:ok, counts})
        loop(map)

      msg ->
        IO.puts(:stderr, "Unexpected message: #{IO.inspect(msg)}")
        loop(map)
    end
  end
end

Main.run()
