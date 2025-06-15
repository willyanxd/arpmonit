import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { 
  Network, 
  Activity, 
  Settings, 
  Bell,
  Shield,
  Zap
} from 'lucide-react';
import { useApp } from '../context/AppContext';

interface LayoutProps {
  children: React.ReactNode;
}

function Layout({ children }: LayoutProps) {
  const location = useLocation();
  const { notifications } = useApp();
  
  const unreadCount = notifications.filter(n => !n.read).length;
  
  const navItems = [
    { path: '/', label: 'Dashboard', icon: Activity },
    { path: '/jobs', label: 'Jobs', icon: Network },
  ];

  return (
    <div className="flex h-screen bg-dark-950">
      {/* Sidebar */}
      <div className="w-64 bg-dark-900 border-r border-dark-700">
        <div className="p-6">
          {/* Logo */}
          <div className="flex items-center space-x-3 mb-8">
            <div className="w-10 h-10 bg-gradient-to-r from-neon-cyan to-neon-purple rounded-lg flex items-center justify-center">
              <Shield className="w-6 h-6 text-white" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-white">ARP Monitor</h1>
              <p className="text-xs text-dark-400">Network Guardian</p>
            </div>
          </div>

          {/* Navigation */}
          <nav className="space-y-2">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = location.pathname === item.path;
              
              return (
                <Link
                  key={item.path}
                  to={item.path}
                  className={`flex items-center space-x-3 px-4 py-3 rounded-lg transition-all duration-200 ${
                    isActive
                      ? 'bg-neon-cyan/10 text-neon-cyan border border-neon-cyan/20 shadow-lg'
                      : 'text-dark-300 hover:text-white hover:bg-dark-800'
                  }`}
                >
                  <Icon className="w-5 h-5" />
                  <span className="font-medium">{item.label}</span>
                </Link>
              );
            })}
          </nav>
        </div>

        {/* Status Indicator */}
        <div className="absolute bottom-6 left-6 right-6">
          <div className="bg-dark-800 rounded-lg p-4 border border-dark-700">
            <div className="flex items-center space-x-3">
              <div className="w-3 h-3 rounded-full bg-neon-green animate-pulse"></div>
              <div>
                <p className="text-sm font-medium text-white">System Active</p>
                <p className="text-xs text-dark-400">Monitoring network</p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 flex flex-col">
        {/* Top Bar */}
        <header className="bg-dark-900 border-b border-dark-700 px-6 py-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-semibold text-white">
                {location.pathname === '/' && 'Dashboard Overview'}
                {location.pathname === '/jobs' && 'Job Management'}
                {location.pathname.startsWith('/jobs/') && 'Job Details'}
              </h2>
              <p className="text-sm text-dark-400">
                Real-time network monitoring and device tracking
              </p>
            </div>
            
            <div className="flex items-center space-x-4">
              {/* Notifications */}
              <div className="relative">
                <button className="p-2 rounded-lg bg-dark-800 hover:bg-dark-700 transition-colors">
                  <Bell className="w-5 h-5 text-dark-300" />
                  {unreadCount > 0 && (
                    <span className="absolute -top-1 -right-1 w-5 h-5 bg-neon-orange rounded-full flex items-center justify-center text-xs font-bold text-white animate-pulse-neon">
                      {unreadCount}
                    </span>
                  )}
                </button>
              </div>

              {/* Settings */}
              <button className="p-2 rounded-lg bg-dark-800 hover:bg-dark-700 transition-colors">
                <Settings className="w-5 h-5 text-dark-300" />
              </button>
            </div>
          </div>
        </header>

        {/* Content Area */}
        <main className="flex-1 overflow-auto bg-dark-950 p-6">
          {children}
        </main>
      </div>
    </div>
  );
}

export default Layout;