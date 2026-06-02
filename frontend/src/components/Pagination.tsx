interface Props {
  total: number;
  limit: number;
  offset: number;
  onChange: (offset: number) => void;
}

export default function Pagination({ total, limit, offset, onChange }: Props) {
  const totalPages = Math.ceil(total / limit);
  const currentPage = Math.floor(offset / limit) + 1;

  if (totalPages <= 1) return null;

  const pages: (number | '...')[] = [];
  const delta = 2;
  for (let i = 1; i <= totalPages; i++) {
    if (i === 1 || i === totalPages || (i >= currentPage - delta && i <= currentPage + delta)) {
      pages.push(i);
    } else if (pages[pages.length - 1] !== '...') {
      pages.push('...');
    }
  }

  return (
    <div className="pagination">
      <button disabled={currentPage <= 1} onClick={() => onChange(offset - limit)}>上一页</button>
      {pages.map((p, i) =>
        p === '...' ? (
          <span key={`dots-${i}`} className="pagination-dots">...</span>
        ) : (
          <button
            key={p}
            className={p === currentPage ? 'active' : ''}
            onClick={() => onChange((p - 1) * limit)}
          >
            {p}
          </button>
        )
      )}
      <button disabled={currentPage >= totalPages} onClick={() => onChange(offset + limit)}>下一页</button>
      <span className="pagination-info">共 {total} 条</span>
    </div>
  );
}
