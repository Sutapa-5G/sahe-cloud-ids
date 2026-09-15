export function EmptyState({ title, detail, tone = 'neutral' }) {
  return (
    <div className={`empty-state empty-state-${tone}`}>
      <p className="empty-state-title">{title}</p>
      {detail && <p className="empty-state-detail">{detail}</p>}
    </div>
  );
}
