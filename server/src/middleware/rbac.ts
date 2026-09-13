import type { NextFunction, Request, Response } from 'express';
import type { ModuleAdminRole } from './auth.js';

const hierarchy: Record<ModuleAdminRole, number> = {
  viewer: 1,
  editor: 2,
  admin: 3,
};

export function requireRole(minRole: ModuleAdminRole) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const role = req.moduleAdmin?.role;
    if (!role) {
      res.status(401).json({
        success: false,
        error: 'Authentication required',
      });
      return;
    }

    if (hierarchy[role] < hierarchy[minRole]) {
      res.status(403).json({
        success: false,
        error: `Insufficient permissions. Required role: ${minRole}`,
      });
      return;
    }

    next();
  };
}

export const requireViewer = requireRole('viewer');
export const requireEditor = requireRole('editor');
export const requireAdmin = requireRole('admin');
