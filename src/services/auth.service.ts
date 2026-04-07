import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
import {
  generateAccessToken,
  generateRefreshToken,
  verifyRefreshToken,
  JwtPayload,
} from '../utils/jwt';

const prisma = new PrismaClient();

const REFRESH_TOKEN_EXPIRES_DAYS = 7;

function refreshTokenExpiryDate(): Date {
  const date = new Date();
  date.setDate(date.getDate() + REFRESH_TOKEN_EXPIRES_DAYS);
  return date;
}

export async function registerUser(
  email: string,
  password: string,
  name?: string
): Promise<{ accessToken: string; refreshToken: string }> {
  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) {
    const error = new Error('Email already in use') as Error & { statusCode: number };
    error.statusCode = 409;
    throw error;
  }

  const hashedPassword = await bcrypt.hash(password, 12);
  const user = await prisma.user.create({
    data: { email, password: hashedPassword, name },
  });

  const payload: JwtPayload = { userId: user.id, email: user.email };
  const accessToken = generateAccessToken(payload);
  const refreshToken = generateRefreshToken(payload);

  await prisma.refreshToken.create({
    data: {
      token: refreshToken,
      userId: user.id,
      expiresAt: refreshTokenExpiryDate(),
    },
  });

  return { accessToken, refreshToken };
}

export async function loginUser(
  email: string,
  password: string
): Promise<{ accessToken: string; refreshToken: string }> {
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) {
    const error = new Error('Invalid credentials') as Error & { statusCode: number };
    error.statusCode = 401;
    throw error;
  }

  const passwordMatch = await bcrypt.compare(password, user.password);
  if (!passwordMatch) {
    const error = new Error('Invalid credentials') as Error & { statusCode: number };
    error.statusCode = 401;
    throw error;
  }

  const payload: JwtPayload = { userId: user.id, email: user.email };
  const accessToken = generateAccessToken(payload);
  const refreshToken = generateRefreshToken(payload);

  await prisma.refreshToken.create({
    data: {
      token: refreshToken,
      userId: user.id,
      expiresAt: refreshTokenExpiryDate(),
    },
  });

  return { accessToken, refreshToken };
}

export async function refreshAccessToken(
  incomingRefreshToken: string
): Promise<{ accessToken: string }> {
  const stored = await prisma.refreshToken.findUnique({
    where: { token: incomingRefreshToken },
  });

  if (!stored || stored.expiresAt < new Date()) {
    const error = new Error('Invalid or expired refresh token') as Error & { statusCode: number };
    error.statusCode = 401;
    throw error;
  }

  let payload: JwtPayload;
  try {
    payload = verifyRefreshToken(incomingRefreshToken);
  } catch {
    const error = new Error('Invalid refresh token') as Error & { statusCode: number };
    error.statusCode = 401;
    throw error;
  }

  const accessToken = generateAccessToken({ userId: payload.userId, email: payload.email });
  return { accessToken };
}

export async function logoutUser(refreshToken: string): Promise<void> {
  await prisma.refreshToken.deleteMany({ where: { token: refreshToken } });
}

export async function getUserById(
  userId: string
): Promise<{ id: string; email: string; name: string | null; createdAt: Date; updatedAt: Date }> {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { id: true, email: true, name: true, createdAt: true, updatedAt: true },
  });

  if (!user) {
    const error = new Error('User not found') as Error & { statusCode: number };
    error.statusCode = 404;
    throw error;
  }

  return user;
}
