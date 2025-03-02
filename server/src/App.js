import React, { useState, useEffect } from 'react';
import { io } from 'socket.io-client';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { AlertCircle, Server, Activity, Shield, Database, NetworkIcon, ArrowUpDown } from 'lucide-react';
import './index.css';

// Connect to the Flask backend
const socket = io('http://localhost:5000', {
  reconnectionAttempts: 5,
  reconnectionDelay: 1000,
  transports: ['websocket'], // Force WebSocket transport
});

function Dashboard() {
  const [packets, setPackets] = useState([]);
  const [requestRates, setRequestRates] = useState([]);
  const [portStatus, setPortStatus] = useState({});
  const [alerts, setAlerts] = useState([]);
  const [activeTab, setActiveTab] = useState('dashboard');
  const [error, setError] = useState(null);
  const [isConnected, setIsConnected] = useState(socket.connected); // Reflect initial connection state
  const [stats, setStats] = useState({
    totalPackets: 0,
    uniqueIPs: new Set(),
    trafficBaseline: { mean: 0, std_dev: 0 },
  });
  const [trafficFilter, setTrafficFilter] = useState('all');

  useEffect(() => {
    const fetchData = async (url, setter) => {
      try {
        const res = await fetch(url);
        if (!res.ok) throw new Error(`Failed to fetch from ${url}: ${res.status}`);
        const data = await res.json();
        setter(data);
      } catch (err) {
        setError(prev => prev ? `${prev}; ${err.message}` : err.message);
      }
    };

    // Initial data fetch
    fetchData('http://localhost:5000/api/packets/recent', setPackets);
    fetchData('http://localhost:5000/api/stats/request_rate', setRequestRates);
    fetchData('http://localhost:5000/api/ports', setPortStatus);
    fetchData('http://localhost:5000/api/alerts', setAlerts);

    // Socket connection handlers
    const onConnect = () => {
      console.log('Connected to server');
      setIsConnected(true);
      setError(null);
      // Fetch initial data on reconnect
      fetchData('http://localhost:5000/api/packets/recent', setPackets);
      fetchData('http://localhost:5000/api/alerts', setAlerts);
    };

    const onDisconnect = () => {
      console.log('Disconnected from server');
      setIsConnected(false);
      setError('Disconnected from server');
    };

    const onConnectError = (err) => {
      console.error('Connection error:', err.message);
      setError(`Failed to connect: ${err.message}`);
      setIsConnected(false);
    };

    // Socket data handlers
    const onNewPacket = (packet) => {
      console.log('New packet received:', packet);
      setPackets(prev => {
        const newPackets = [...prev.slice(-99), packet];
        return newPackets;
      });
      setStats(prev => ({
        ...prev,
        totalPackets: prev.totalPackets + 1,
        uniqueIPs: new Set([...prev.uniqueIPs, packet.src_ip, packet.dst_ip]),
      }));
    };

    const onRequestRate = (rate) => {
      console.log('Request rate received:', rate);
      setRequestRates(prev => [...prev.slice(-299), rate]);
    };

    const onPortStatus = (status) => {
      console.log('Port status received:', status);
      setPortStatus(status);
    };

    const onPortChange = (change) => {
      console.log('Port change received:', change);
      setAlerts(prev => [...prev, {
        id: Date.now(),
        type: 'port',
        message: `Port ${change.port} opened by ${change.program}`,
        timestamp: new Date().toISOString(),
        severity: 'warning',
      }]);
    };

    const onAnomalyAlert = (anomaly) => {
      console.log('Anomaly alert received:', anomaly);
      setAlerts(prev => [...prev, {
        id: Date.now(),
        type: 'traffic',
        message: `Traffic spike detected! ${anomaly.current_rate.toFixed(1)} req/s (${anomaly.increase_factor.toFixed(1)}x normal)`,
        timestamp: new Date().toISOString(),
        severity: 'high',
      }]);
      playAlertSound();
    };

    const onHttpAttack = (attack) => {
      console.log('HTTP attack received:', attack);
      setAlerts(prev => [...prev, {
        id: Date.now(),
        type: 'http_attack',
        message: `Attack detected from ${attack.src_ip}: ${attack.attack_types.join(', ')}`,
        timestamp: new Date().toISOString(),
        severity: attack.severity || 'critical',
      }]);
      playAlertSound();
    };

    const onSpoofingAlert = (spoof) => {
      console.log('Spoofing alert received:', spoof);
      setAlerts(prev => [...prev, {
        id: Date.now(),
        type: 'spoofing',
        message: `Spoofed IP detected: ${spoof.src_ip} → ${spoof.dst_ip}`,
        timestamp: new Date().toISOString(),
        severity: 'high',
      }]);
      playAlertSound();
    };

    const playAlertSound = () => {
      try {
        const audio = new Audio('/alert.mp3');
        audio.play().catch(err => console.warn('Alert sound blocked:', err));
      } catch (err) {
        console.warn('Alert sound failed:', err);
      }
    };

    // Attach listeners
    socket.on('connect', onConnect);
    socket.on('disconnect', onDisconnect);
    socket.on('connect_error', onConnectError);
    socket.on('new_packet', onNewPacket);
    socket.on('request_rate', onRequestRate);
    socket.on('port_status', onPortStatus);
    socket.on('port_change', onPortChange);
    socket.on('anomaly_alert', onAnomalyAlert);
    socket.on('http_attack', onHttpAttack);
    socket.on('spoofing_alert', onSpoofingAlert);

    // Manual connection attempt
    if (!socket.connected) {
      console.log('Attempting to connect manually...');
      socket.connect();
    }

    // Cleanup
    return () => {
      socket.off('connect', onConnect);
      socket.off('disconnect', onDisconnect);
      socket.off('connect_error', onConnectError);
      socket.off('new_packet', onNewPacket);
      socket.off('request_rate', onRequestRate);
      socket.off('port_status', onPortStatus);
      socket.off('port_change', onPortChange);
      socket.off('anomaly_alert', onAnomalyAlert);
      socket.off('http_attack', onHttpAttack);
      socket.off('spoofing_alert', onSpoofingAlert);
    };
  }, []);

  // Filter packets based on selected protocol
  const filteredPackets = React.useMemo(() => {
    if (trafficFilter === 'all') return packets;
    return packets.filter(packet =>
      packet.protocol && packet.protocol.toLowerCase() === trafficFilter.toLowerCase()
    );
  }, [packets, trafficFilter]);

  const formatTimestamp = (timestamp) => {
    if (!timestamp) return 'N/A';
    const date = typeof timestamp === 'string' ? new Date(timestamp) : new Date(timestamp * 1000);
    return date.toLocaleTimeString([], { hour12: true, hour: '2-digit', minute: '2-digit', second: '2-digit' });
  };

  const getSeverityColor = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical': return 'border-red-600 bg-red-50';
      case 'high': return 'border-red-500 bg-red-50';
      case 'warning': return 'border-yellow-500 bg-yellow-50';
      default: return 'border-gray-400 bg-gray-50';
    }
  };

  const protocolDistribution = React.useMemo(() => {
    const counts = {};
    packets.forEach(packet => {
      const protocol = packet.protocol || 'Unknown';
      counts[protocol] = (counts[protocol] || 0) + 1;
    });
    return counts;
  }, [packets]);

  const trafficTrend = React.useMemo(() => {
    if (requestRates.length < 10) return { change: 0, direction: 'stable' };
    const recent = requestRates.slice(-5).reduce((sum, item) => sum + item.count, 0) / 5;
    const previous = requestRates.slice(-10, -5).reduce((sum, item) => sum + item.count, 0) / 5;
    const change = previous === 0 ? 0 : ((recent - previous) / previous * 100);
    let direction = 'stable';
    if (change > 10) direction = 'increasing';
    if (change < -10) direction = 'decreasing';
    return { change, direction };
  }, [requestRates]);

  return (
    <div className="flex flex-col min-h-screen bg-gray-100">
      {error && (
        <div className="bg-red-500 text-white p-2 text-center">
          Error: {error}
        </div>
      )}
      <header className="bg-gray-800 text-white p-4">
        <div className="container mx-auto flex justify-between items-center">
          <h1 className="text-2xl font-bold">Threat Detection & Monitoring Platform</h1>
          <div className="flex items-center">
            <span className={`inline-block w-3 h-3 rounded-full mr-2 ${isConnected ? 'bg-green-500' : 'bg-red-500'}`}></span>
            <span className="text-sm">{isConnected ? 'Connected' : 'Disconnected'}</span>
          </div>
        </div>
      </header>

      <nav className="bg-gray-700 text-white">
        <div className="container mx-auto flex">
          {['dashboard', 'packets', 'ports', 'alerts', 'stats'].map(tab => (
            <button
              key={tab}
              className={`px-4 py-2 ${activeTab === tab ? 'bg-blue-600' : ''}`}
              onClick={() => setActiveTab(tab)}
            >
              {tab.charAt(0).toUpperCase() + tab.slice(1)}
              {/* {tab === 'alerts' && alerts.length > 0 && (
                <span className="ml-2 bg-red-500 text-white rounded-full px-2 py-1 text-xs">
                  {alerts.length}
                </span>
              )} */}
            </button>
          ))}
        </div>
      </nav>

      <main className="flex-grow p-4">
        <div className="container mx-auto">
          {activeTab === 'dashboard' && (
            <div className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div className="bg-white p-4 rounded shadow flex items-center">
                  <div className="rounded-full bg-blue-100 p-3 mr-4">
                    <Activity className="text-blue-600" />
                  </div>
                  <div>
                    <h3 className="text-gray-500 text-sm">Traffic Trend</h3>
                    <div className="flex items-center">
                      <span className="text-xl font-semibold">{Math.abs(trafficTrend.change).toFixed(1)}%</span>
                      {trafficTrend.direction !== 'stable' && (
                        <ArrowUpDown className={`ml-2 ${trafficTrend.direction === 'increasing' ? 'text-red-500 transform rotate-180' : 'text-green-500'}`} />
                      )}
                    </div>
                  </div>
                </div>
                <div className="bg-white p-4 rounded shadow flex items-center">
                  <div className="rounded-full bg-green-100 p-3 mr-4">
                    <NetworkIcon className="text-green-600" />
                  </div>
                  <div>
                    <h3 className="text-gray-500 text-sm">Active IPs</h3>
                    <p className="text-xl font-semibold">{stats.uniqueIPs.size}</p>
                  </div>
                </div>
                <div className="bg-white p-4 rounded shadow flex items-center">
                  <div className="rounded-full bg-purple-100 p-3 mr-4">
                    <Database className="text-purple-600" />
                  </div>
                  <div>
                    <h3 className="text-gray-500 text-sm">Total Packets</h3>
                    <p className="text-xl font-semibold">{stats.totalPackets}</p>
                  </div>
                </div>
                <div className="bg-white p-4 rounded shadow flex items-center">
                  <div className="rounded-full bg-red-100 p-3 mr-4">
                    <Shield className="text-red-600" />
                  </div>
                  <div>
                    <h3 className="text-gray-500 text-sm">Security Alerts</h3>
                    <p className="text-xl font-semibold">{alerts.length}</p>
                  </div>
                </div>
              </div>
              <div className="bg-white p-4 rounded shadow">
                <div className="flex justify-between items-center mb-4">
                  <h2 className="text-xl font-semibold flex items-center">
                    <Activity className="mr-2" /> Traffic Monitor
                  </h2>
                  <div className="flex space-x-2">
                    {['all', 'http', 'tcp', 'udp'].map(filter => (
                      <button
                        key={filter}
                        className={`px-3 py-1 text-sm rounded ${trafficFilter === filter ? 'bg-blue-600 text-white' : 'bg-gray-200'}`}
                        onClick={() => setTrafficFilter(filter)}
                      >
                        {filter.toUpperCase()}
                      </button>
                    ))}
                  </div>
                </div>
                <div className="h-64">
                  {requestRates.length > 0 ? (
                    <ResponsiveContainer width="100%" height="100%">
                      <LineChart data={requestRates.map(r => ({
                        time: formatTimestamp(r.timestamp),
                        value: r.count,
                      }))}>
                        <CartesianGrid strokeDasharray="3 3" />
                        <XAxis dataKey="time" />
                        <YAxis />
                        <Tooltip />
                        <Line type="monotone" dataKey="value" stroke="#3b82f6" strokeWidth="2" dot={false} />
                      </LineChart>
                    </ResponsiveContainer>
                  ) : (
                    <p className="text-gray-500">Loading traffic data...</p>
                  )}
                </div>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="bg-white p-4 rounded shadow">
                  <h2 className="text-xl font-semibold mb-4 flex items-center">
                    <Server className="mr-2" /> Open Ports
                  </h2>
                  <div className="flex flex-wrap gap-4">
                    {Object.entries(portStatus).length > 0 ? (
                      Object.entries(portStatus).map(([port, info]) => (
                        <div key={port} className="flex items-center space-x-2">
                          <div
                            className={`w-4 h-4 rounded-full ${info.status === 'OPEN' ? 'bg-green-500' : 'bg-gray-400'}`}
                            title={`${info.status} - ${info.program}`}
                          ></div>
                          <span className="text-sm font-medium">{port}</span>
                          <span className="text-sm text-gray-600">({info.program})</span>
                        </div>
                      ))
                    ) : (
                      <p className="text-gray-500">No open ports detected</p>
                    )}
                  </div>
                </div>
                <div className="bg-white p-4 rounded shadow">
                  <h2 className="text-xl font-semibold mb-4 flex items-center">
                    <AlertCircle className="mr-2" /> Recent Threats
                  </h2>
                  <div className="overflow-y-auto max-h-64">
                    {alerts.length > 0 ? (
                      <ul className="divide-y">
                        {alerts.slice(-5).reverse().map(alert => (
                          <li key={alert.id} className="py-2">
                            <div className={`border-l-4 pl-3 ${getSeverityColor(alert.severity)}`}>
                              <p className="font-medium">{alert.message}</p>
                              <p className="text-sm text-gray-600">{formatTimestamp(alert.timestamp)}</p>
                            </div>
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <p className="text-gray-500">No threats detected</p>
                    )}
                  </div>
                </div>
              </div>
              <div className="bg-white p-4 rounded shadow">
                <h2 className="text-xl font-semibold mb-4">Network Activity (Live Packet Capture)</h2>
                <div className="bg-green-100 p-4 rounded">
                  {filteredPackets.length > 0 ? (
                    <ul className="divide-y">
                      {filteredPackets.slice(-10).reverse().map((packet, i) => (
                        <li key={i} className="py-2 flex justify-between items-center">
                          <div>
                            <span>{packet.src_ip}:{packet.src_port || 'N/A'}</span>
                            <span className="mx-2">→</span>
                            <span>{packet.dst_ip}:{packet.dst_port || 'N/A'}</span>
                          </div>
                          <div className="text-sm text-gray-600">
                            {formatTimestamp(packet.timestamp)} | Protocol: {packet.protocol} | Flags: {packet.flags || 'N/A'}
                          </div>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="text-gray-500">No recent packets</p>
                  )}
                </div>
              </div>
            </div>
          )}
          {activeTab === 'packets' && (
            <div className="bg-white p-4 rounded shadow">
              <div className="flex justify-between items-center mb-4">
                <h2 className="text-xl font-semibold">Packet Monitor</h2>
                <div className="flex space-x-2">
                  {['all', 'http', 'tcp', 'udp'].map(filter => (
                    <button
                      key={filter}
                      className={`px-3 py-1 text-sm rounded ${trafficFilter === filter ? 'bg-blue-600 text-white' : 'bg-gray-200'}`}
                      onClick={() => setTrafficFilter(filter)}
                    >
                      {filter.toUpperCase()}
                    </button>
                  ))}
                </div>
              </div>
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Time</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Source</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Destination</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Protocol</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Flags</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Details</th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {filteredPackets.slice().reverse().map((packet, i) => (
                      <tr key={i} className="hover:bg-gray-50">
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                          {formatTimestamp(packet.timestamp)}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm">
                          {packet.src_ip}:{packet.src_port || 'N/A'}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm">
                          {packet.dst_ip}:{packet.dst_port || 'N/A'}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm">{packet.protocol}</td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm">{packet.flags || 'N/A'}</td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm">
                          {packet.http_method && packet.http_uri ? (
                            <span>{packet.http_method} {packet.http_uri}</span>
                          ) : (
                            <span>-</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
          {/* Ports, Alerts, Stats tabs remain unchanged for brevity */}
          {activeTab === 'ports' && (
            <div className="bg-white p-4 rounded shadow">
              <h2 className="text-xl font-semibold mb-4">Port Scanner</h2>
              <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
                {Object.entries(portStatus).length > 0 ? (
                  Object.entries(portStatus).map(([port, info]) => (
                    <div key={port} className="border p-4 rounded shadow-sm bg-blue-50">
                      <h3 className="text-lg font-medium">Port {port}</h3>
                      <p className="text-sm text-gray-600">Status: {info.status}</p>
                      <p className="text-sm text-gray-600">Program: {info.program}</p>
                    </div>
                  ))
                ) : (
                  <div className="col-span-full text-center py-8">
                    <p className="text-gray-500">No open ports detected</p>
                  </div>
                )}
              </div>
            </div>
          )}
          {activeTab === 'alerts' && (
            <div className="bg-white p-4 rounded shadow">
              <h2 className="text-xl font-semibold mb-4">Alert Log</h2>
              <div className="overflow-y-auto max-h-96">
                {alerts.length > 0 ? (
                  <ul className="divide-y">
                    {alerts.slice().reverse().map(alert => (
                      <li key={alert.id} className="py-3">
                        <div className={`border-l-4 pl-3 ${getSeverityColor(alert.severity)}`}>
                          <p className="font-medium">{alert.message}</p>
                          <p className="text-sm text-gray-600">
                            {formatTimestamp(alert.timestamp)} | Type: {alert.type.charAt(0).toUpperCase() + alert.type.slice(1)} | Severity: {alert.severity?.charAt(0).toUpperCase() + alert.severity?.slice(1)}
                          </p>
                        </div>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-gray-500">No alerts detected</p>
                )}
              </div>
            </div>
          )}
          {activeTab === 'stats' && (
            <div className="space-y-6">
              <div className="bg-white p-4 rounded shadow">
                <h2 className="text-xl font-semibold mb-4">Traffic Statistics</h2>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  {/* Protocol Distribution */}
                  <div>
                    <h3 className="font-medium mb-2">Protocol Distribution</h3>
                    <div className="bg-gray-50 p-4 rounded">
                      {Object.keys(protocolDistribution).length > 0 ? (
                        <ul className="space-y-2">
                          {Object.entries(protocolDistribution).map(([protocol, count]) => (
                            <li key={protocol} className="flex items-center">
                              <span className="w-24 font-medium">{protocol}:</span>
                              <div className="flex-grow bg-gray-200 h-5 rounded overflow-hidden">
                                <div
                                  className="bg-blue-500 h-full"
                                  style={{ width: `${(count / packets.length) * 100}%` }}
                                ></div>
                              </div>
                              <span className="ml-2 text-sm text-gray-600">
                                {count} ({((count / packets.length) * 100).toFixed(1)}%)
                              </span>
                            </li>
                          ))}
                        </ul>
                      ) : (
                        <p className="text-gray-500">No data available</p>
                      )}
                    </div>
                  </div>

                  {/* Traffic Overview */}
                  <div>
                    <h3 className="font-medium mb-2">Traffic Overview</h3>
                    <div className="bg-gray-50 p-4 rounded">
                      <div className="grid grid-cols-2 gap-4">
                        <div className="bg-white p-3 rounded shadow-sm">
                          <p className="text-sm text-gray-500">Total Packets</p>
                          <p className="text-xl font-semibold">{stats.totalPackets}</p>
                        </div>
                        <div className="bg-white p-3 rounded shadow-sm">
                          <p className="text-sm text-gray-500">Unique IPs</p>
                          <p className="text-xl font-semibold">{stats.uniqueIPs.size}</p>
                        </div>
                        <div className="bg-white p-3 rounded shadow-sm">
                          <p className="text-sm text-gray-500">Average Traffic</p>
                          <p className="text-xl font-semibold">
                            {requestRates.length > 0
                              ? (requestRates.reduce((sum, item) => sum + item.count, 0) / requestRates.length).toFixed(1)
                              : '0'} req/s
                          </p>
                        </div>
                        <div className="bg-white p-3 rounded shadow-sm">
                          <p className="text-sm text-gray-500">Traffic Trend</p>
                          <p className="text-xl font-semibold flex items-center">
                            {Math.abs(trafficTrend.change).toFixed(1)}%
                            {trafficTrend.direction !== 'stable' && (
                              <ArrowUpDown className={`ml-2 ${trafficTrend.direction === 'increasing' ? 'text-red-500 transform rotate-180' :
                                trafficTrend.direction === 'decreasing' ? 'text-green-500' : ''
                                }`} />
                            )}
                          </p>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Security Summary */}
              <div className="bg-white p-4 rounded shadow">
                <h2 className="text-xl font-semibold mb-4">Security Summary</h2>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="border rounded p-4">
                    <h3 className="font-medium text-lg mb-2">Alert Severity</h3>
                    <div className="space-y-2">
                      {['critical', 'high', 'warning'].map(severity => {
                        const count = alerts.filter(a => a.severity === severity).length;
                        return (
                          <div key={severity} className="flex items-center">
                            <span className="w-20 capitalize">{severity}:</span>
                            <div className="flex-grow bg-gray-200 h-5 rounded overflow-hidden">
                              <div
                                className={`h-full ${severity === 'critical' ? 'bg-red-600' :
                                  severity === 'high' ? 'bg-red-500' : 'bg-yellow-500'
                                  }`}
                                style={{ width: `${alerts.length ? (count / alerts.length) * 100 : 0}%` }}
                              ></div>
                            </div>
                            <span className="ml-2 text-sm text-gray-600">
                              {count} ({alerts.length ? ((count / alerts.length) * 100).toFixed(1) : 0}%)
                            </span>
                          </div>
                        );
                      })}
                    </div>
                  </div>

                  <div className="border rounded p-4">
                    <h3 className="font-medium text-lg mb-2">Alert Types</h3>
                    <div className="space-y-2">
                      {['http_attack', 'traffic', 'port', 'spoofing'].map(type => {
                        const count = alerts.filter(a => a.type === type).length;
                        return (
                          <div key={type} className="flex items-center">
                            <span className="w-20 capitalize">{type}:</span>
                            <div className="flex-grow bg-gray-200 h-5 rounded overflow-hidden">
                              <div
                                className="bg-blue-500 h-full"
                                style={{ width: `${alerts.length ? (count / alerts.length) * 100 : 0}%` }}
                              ></div>
                            </div>
                            <span className="ml-2 text-sm text-gray-600">
                              {count} ({alerts.length ? ((count / alerts.length) * 100).toFixed(1) : 0}%)
                            </span>
                          </div>
                        );
                      })}
                    </div>
                  </div>

                  <div className="border rounded p-4">
                    <h3 className="font-medium text-lg mb-2">Recent Activity</h3>
                    <div className="space-y-2">
                      <p>Last alert: {alerts.length > 0 ? formatTimestamp(alerts[alerts.length - 1].timestamp) : 'N/A'}</p>
                      <p>Last packet: {packets.length > 0 ? formatTimestamp(packets[packets.length - 1].timestamp) : 'N/A'}</p>
                      <p>Alerts last hour: {alerts.filter(a => {
                        const timestamp = new Date(a.timestamp);
                        const hourAgo = new Date();
                        hourAgo.setHours(hourAgo.getHours() - 1);
                        return timestamp > hourAgo;
                      }).length}</p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </main>

      <footer className="bg-gray-800 text-white p-4 text-center text-sm">
        <p>© 2025 Network Security Monitoring System - All rights reserved</p>
      </footer>
    </div>
  );
}

export default Dashboard;