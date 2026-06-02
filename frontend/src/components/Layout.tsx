import { NavLink, Outlet } from 'react-router-dom';
import styles from './Layout.module.css';

export default function Layout() {
  return (
    <div className={styles.wrapper}>
      <aside className={styles.sidebar}>
        <div className={styles.logo}>eScan</div>
        <nav className={styles.nav}>
          <NavLink to="/" end className={({ isActive }) => isActive ? styles.active : ''}>
            仪表盘
          </NavLink>
          <NavLink to="/templates" className={({ isActive }) => isActive ? styles.active : ''}>
            模板库
          </NavLink>
          <NavLink to="/scan" className={({ isActive }) => isActive ? styles.active : ''}>
            扫描任务
          </NavLink>
          <NavLink to="/vulnerabilities" className={({ isActive }) => isActive ? styles.active : ''}>
            漏洞概览
          </NavLink>
          <NavLink to="/proxy" className={({ isActive }) => isActive ? styles.active : ''}>
            代理池
          </NavLink>
          <NavLink to="/config" className={({ isActive }) => isActive ? styles.active : ''}>
            配置
          </NavLink>
        </nav>
      </aside>
      <main className={styles.main}>
        <Outlet />
      </main>
    </div>
  );
}
