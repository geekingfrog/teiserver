defmodule Teiserver.Tachyon.Schema do
  @moduledoc """

  """

  @spec load_schemas :: list
  def load_schemas() do
    Application.get_env(:teiserver, Teiserver)[:tachyon_schema_path]
    |> Path.wildcard()
    |> Enum.map(fn file_path ->
      contents =
        file_path
        |> File.read!()
        |> Jason.decode!()

      # this doesn't work for responses since they have no commandId, but for now
      # this is fine.
      command = Kernel.get_in(contents, ["properties", "commandId", "const"])

      schema = JsonXema.new(contents)

      Teiserver.store_put(:tachyon_schemas, command, schema)
      command
    end)
  end

  @spec validate!(map) :: :ok
  def validate!(%{"commandId" => command} = object) do
    schema = get_schema(command)
    JsonXema.validate!(schema, object)
  end

  defp get_schema(command) do
    ConCache.get(:tachyon_schemas, command)
  end
end
