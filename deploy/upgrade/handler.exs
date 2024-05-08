defmodule Handler do
  def main([key, config]) do
    {:ok, [config]} = :file.consult(config)

    case key do
      "all_keys" ->
        IO.write(inspect(config, pretty: true))
      "name" ->
        regions = Enum.join(config[:regions], "&")

        IO.write(
          "supavisor_#{config[:type]}_#{regions}_#{config[:upgrade_from]}_#{config[:upgrade_to]}"
        )

      key ->
        IO.write(config[String.to_atom(key)])
    end

  end
end


Handler.main(System.argv())
