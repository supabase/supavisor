defmodule SupavisorWeb.TenantViewTest do
  use ExUnit.Case
  alias SupavisorWeb.TenantView

  describe "render/2 for not_found.json" do
    test "returns a not found error message" do
      assert TenantView.render("not_found.json", %{}) == %{error: "not found"}
    end
  end
end
