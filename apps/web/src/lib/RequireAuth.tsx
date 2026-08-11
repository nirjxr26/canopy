import { Navigate, Outlet, useLocation } from "react-router-dom";
import { useAuth } from "../lib/auth";

export function RequireAuth() {
  const { user, loading } = useAuth();
  const location = useLocation();

  if (loading) {
    return (
      <div className="auth-shell">
        <span className="spinner spinner--plain" aria-hidden="true" />
      </div>
    );
  }

  if (user === null) {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  }

  return <Outlet />;
}
