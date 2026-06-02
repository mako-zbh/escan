import styles from './StatsCard.module.css';

interface Props {
  title: string;
  value: number | string;
  icon?: string;
  loading?: boolean;
}

export default function StatsCard({ title, value, icon, loading }: Props) {
  return (
    <div className={styles.card}>
      {icon && <span className={styles.icon}>{icon}</span>}
      <div className={styles.info}>
        <span className={styles.title}>{title}</span>
        <span className={styles.value}>{loading ? '...' : value}</span>
      </div>
    </div>
  );
}
