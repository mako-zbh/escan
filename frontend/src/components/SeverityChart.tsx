import { useEffect, useRef } from 'react';
import * as echarts from 'echarts';
import { severityColor } from '../utils/format';

interface Props {
  data: Record<string, number>;
}

export default function SeverityChart({ data }: Props) {
  const chartRef = useRef<HTMLDivElement>(null);
  const instanceRef = useRef<echarts.ECharts | null>(null);

  useEffect(() => {
    if (!chartRef.current) return;

    if (!instanceRef.current) {
      instanceRef.current = echarts.init(chartRef.current);
    }

    const chartData = Object.entries(data)
      .filter(([, c]) => c > 0)
      .map(([name, value]) => ({ name, value }));

    instanceRef.current.setOption({
      tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
      series: [
        {
          type: 'pie',
          radius: ['45%', '75%'],
          center: ['50%', '50%'],
          label: { show: true, formatter: '{b}\n{d}%' },
          data: chartData,
          itemStyle: {
            color: (params: { name: string }) => severityColor(params.name),
          },
          emphasis: {
            itemStyle: { shadowBlur: 10, shadowColor: 'rgba(0,0,0,0.2)' },
          },
        },
      ],
    });

    const handleResize = () => instanceRef.current?.resize();
    window.addEventListener('resize', handleResize);

    return () => {
      window.removeEventListener('resize', handleResize);
    };
  }, [data]);

  return <div ref={chartRef} style={{ width: '100%', height: 320 }} />;
}
