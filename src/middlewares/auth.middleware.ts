import { NextFunction, Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import redisClient from '../db/redis';
export type RequestCustom = Request & { userId?: string; accessToken?: string };
export type IPayload = jwt.JwtPayload & { userId?: string };
export const verifyToken = (req: RequestCustom, res: Response, next: NextFunction) => {
    const tokenString = req.headers.authorization;
    if (tokenString) {
        const accessToken = tokenString.split(' ')[1];
        jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET!, async (error, decoded) => {
            if (error) {
                if (error.name === 'TokenExpiredError')
                    return res.status(401).json({
                        message: 'Token expired',
                    });
                else if (error.name === 'JsonWebTokenError') {
                    return res.status(400).json({
                        message: error.message,
                    });
                } else {
                    return res.status(400).json({
                        message: error?.message,
                    });
                }
            } else {
                const data = decoded as IPayload;
                const dataStore = await redisClient.get('BL_' + data.userId?.toString());
                if (dataStore == accessToken) {
                    return res.status(401).json({
                        message: 'Token inside blacklisted',
                    });
                } else {
                    req.userId = data?.userId;
                    req.accessToken = accessToken;
                    next();
                }
            }
        });
    } else {
        return res.status(401).json({
            message: 'Token not found',
        });
    }
};
