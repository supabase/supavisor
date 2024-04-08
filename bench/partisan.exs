alias Supavisor.Helpers, as: H

long = <<51, 0, 0, 0, 4, 90, 0, 0, 0, 5, 84>>
short = <<90, 0, 0, 0, 5, 84>>
empty = <<>>
pattern = <<?Z, 5::32, ?I>>

Benchee.run(%{
  # "pid -> partisan pid" => fn ->
  #   H.pertisan_pid(self())
  # end
  "term_to_binary" => fn ->
    {self(), node(), make_ref()}
    |> :erlang.term_to_binary()
    |> :erlang.binary_to_term()
  end
})
