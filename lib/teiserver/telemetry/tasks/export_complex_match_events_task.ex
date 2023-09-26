defmodule Teiserver.Telemetry.ExportComplexMatchEventsTask do
  @moduledoc false
  alias Teiserver.Telemetry.ComplexMatchEvent
  alias Teiserver.Helper.{DatePresets}
  alias Teiserver.Repo
  import Ecto.Query, warn: false
  import Teiserver.Helper.QueryHelpers

  @spec perform(map) :: map()
  def perform(%{"event_types" => event_types, "timeframe" => timeframe}) do
    {start_date, end_date} = DatePresets.parse(timeframe, "", "")

    start_date = Timex.to_datetime(start_date)
    end_date = Timex.to_datetime(end_date)

    %{
      "complex_match_events" => query_client(event_types, start_date, end_date)
    }
  end

  def perform(_) do
    %{}
  end

  defp query_client(event_types, start_date, end_date) do
    query =
      from complex_match_events in ComplexMatchEvent,
        where: complex_match_events.event_type_id in ^event_types,
        where: between(complex_match_events.timestamp, ^start_date, ^end_date),
        join: event_types in assoc(complex_match_events, :event_type),
        join: users in assoc(complex_match_events, :user),
        select: [users.name, event_types.name, complex_match_events.timestamp, complex_match_events.value]

    stream = Repo.stream(query, max_rows: 500)

    {:ok, result} =
      Repo.transaction(fn ->
        stream
        |> Enum.map(fn [name, event_type, timestamp, value] ->
          %{
            name: name,
            event: event_type,
            timestamp: timestamp,
            value: value
          }
        end)
        |> Enum.to_list()
      end)

    result
  end
end