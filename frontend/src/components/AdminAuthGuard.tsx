// Admin Auth Guard Component
// Requirements: 6.1

import { Navigate, useLocation } from 'react-router-dom';
import type { ReactNode } from 'react';
import { isAuthenticated } from '../services/adminApi';

interface AdminAuthGuardProps {
  children: ReactNode;
}

export function AdminAuthGuard({ children }: AdminAuthGuardProps) {
  const location = useLocation();

  if (!isAuthenticated()) {
    // Redirect to login, preserving the intended destination
    return <Navigate to="/admin/login" state={{ from: location }} replace />;
  }

  return <>{children}</>;
}
