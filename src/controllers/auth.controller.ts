import { Request, Response, NextFunction } from 'express';
import * as authService from '../services/auth.service';

const REFRESH_TOKEN_COOKIE = 'refreshToken';
const COOKIE_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

function setRefreshTokenCookie(res: Response, token: string): void {
  res.cookie(REFRESH_TOKEN_COOKIE, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: COOKIE_MAX_AGE_MS,
  });
}

export async function register(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const { email, password, name } = req.body as {
      email?: string;
      password?: string;
      name?: string;
    };

    if (!email || !password) {
      res.status(400).json({ message: 'Email and password are required' });
      return;
    }

    const { accessToken, refreshToken } = await authService.registerUser(email, password, name);
    setRefreshTokenCookie(res, refreshToken);
    res.status(201).json({ accessToken });
  } catch (err) {
    next(err);
  }
}

export async function login(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const { email, password } = req.body as { email?: string; password?: string };

    if (!email || !password) {
      res.status(400).json({ message: 'Email and password are required' });
      return;
    }

    const { accessToken, refreshToken } = await authService.loginUser(email, password);
    setRefreshTokenCookie(res, refreshToken);
    res.status(200).json({ accessToken });
  } catch (err) {
    next(err);
  }
}

export async function refresh(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const incomingRefreshToken = req.cookies[REFRESH_TOKEN_COOKIE] as string | undefined;

    if (!incomingRefreshToken) {
      res.status(401).json({ message: 'Refresh token missing' });
      return;
    }

    const { accessToken } = await authService.refreshAccessToken(incomingRefreshToken);
    res.status(200).json({ accessToken });
  } catch (err) {
    next(err);
  }
}

export async function logout(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const incomingRefreshToken = req.cookies[REFRESH_TOKEN_COOKIE] as string | undefined;

    if (incomingRefreshToken) {
      await authService.logoutUser(incomingRefreshToken);
    }

    res.clearCookie(REFRESH_TOKEN_COOKIE, { httpOnly: true, sameSite: 'strict' });
    res.status(200).json({ message: 'Logged out successfully' });
  } catch (err) {
    next(err);
  }
}

export async function getMe(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const userId = (req as Request & { userId?: string }).userId;
    if (!userId) {
      res.status(401).json({ message: 'Unauthorized' });
      return;
    }

    const user = await authService.getUserById(userId);
    res.status(200).json({ user });
  } catch (err) {
    next(err);
  }
}
