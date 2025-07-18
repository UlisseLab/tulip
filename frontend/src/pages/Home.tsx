const shortcutTableData = [
  [
    { key: "j/k", action: "Down/Up in FlowList" },
    { key: "s", action: "Focus search bar" },
    { key: "esc", action: "Unfocus search bar" },
    { key: "i/o", action: "Toggle flag in/out filters" },
  ],
  [
    { key: "h/l", action: "Up/Down in Flow" },
    { key: "a", action: "Last 5 ticks" },
    { key: "c", action: "Clear time selection" },
    { key: "r", action: "Refresh flows" },
  ],
  [
    { key: "d", action: "Diff view" },
    { key: "f", action: "Load flow to first diff slot" },
    { key: "g", action: "Load flow to second diff slot" },
  ],
];

function generateShortcutTable(data: { key: string; action: string }[][]) {
  return (
    <div className="flex flex-row gap-4">
      {data.map((table, tableIndex) => (
        <table
          key={tableIndex}
          className="border-collapse border border-slate-500 table-auto"
        >
          <thead>
            <tr>
              <th className="border border-slate-600 px-4">Key</th>
              <th className="border border-slate-600 px-4">Action</th>
            </tr>
          </thead>
          <tbody>
            {table.map((row) => (
              <tr key={row.action}>
                {Object.entries(row).map((cell, cellIndex) => (
                  <td className="border border-slate-700 px-4" key={cellIndex}>
                    {cell[1]}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      ))}
    </div>
  );
}

export function Home() {
  return (
    <div className="p-4 flex flex-col justify-center items-center h-full opacity-40">
      <span className="text-9xl mb-4">🌷</span>
      <h1 className="text-5xl text-gray-600">Welcome to Tulip</h1>
      <span className="text-xl">(Ulisse Edition)</span>

      <h1 className="text-2xl text-gray-500 mt-8">Shortcut reference:</h1>
      {generateShortcutTable(shortcutTableData)}
    </div>
  );
}
