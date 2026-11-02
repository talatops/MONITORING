import Dashboard from "./components/Dashboard";
import { useMonitorWebSocket } from "./hooks/useMonitorWebSocket";

export default function App() {
  const state = useMonitorWebSocket();
  return <Dashboard state={state} />;
}
