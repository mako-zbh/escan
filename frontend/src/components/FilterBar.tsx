interface Props {
  search: string;
  severity: string;
  hasIcp: string;
  onSearchChange: (v: string) => void;
  onSeverityChange: (v: string) => void;
  onHasIcpChange: (v: string) => void;
}

export default function FilterBar({ search, severity, hasIcp, onSearchChange, onSeverityChange, onHasIcpChange }: Props) {
  return (
    <div className="filter-bar">
      <input
        type="text"
        className="input"
        placeholder="搜索模板名称..."
        value={search}
        onChange={e => onSearchChange(e.target.value)}
        style={{ width: 220 }}
      />
      <select className="input" value={severity} onChange={e => onSeverityChange(e.target.value)}>
        <option value="">全部级别</option>
        <option value="critical">Critical</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
        <option value="info">Info</option>
      </select>
      <select className="input" value={hasIcp} onChange={e => onHasIcpChange(e.target.value)}>
        <option value="">ICP: 全部</option>
        <option value="1">ICP: 有备案</option>
        <option value="0">ICP: 无备案</option>
      </select>
    </div>
  );
}
