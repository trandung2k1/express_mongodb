import { NextFunction, Request, Response } from 'express';
import jwt from 'jsonwebtoken';
type RequestCustom = Request & { userId?: string };
type IPayload = jwt.JwtPayload & { userId?: string };
export const verifyToken = (req: RequestCustom, res: Response, next: NextFunction) => {
    const tokenString = req.headers.authorization;
    if (tokenString) {
        const accessToken = tokenString.split(' ')[1];
        jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET!, (error, decoded) => {
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
                console.log(data.userId);
                // req.userId = decoded?.userId;
                next();
            }
        });
    } else {
        return res.status(401).json({
            message: 'Token not found',
        });
    }
};
// export const verifyTokenAndUserAuthorization = (
//     req: RequestCustom,
//     res: Response,
//     next: NextFunction,
// ) => {
//     verifyToken(req, res, () => {
//         if (req.user.userId === req.params.id) {
//             next();
//         } else {
//             return res.status(403).json("You're not allowed to do that!");
//         }
//     });
// };
// export const verifyTokenAndAdmin = (req: RequestCustom, res: Response, next: NextFunction) => {
//     verifyToken(req, res, () => {
//         if (req.user.userId) {
//             next();
//         } else {
//             return res.status(403).json("You're not allowed to do that!");
//         }
//     });
// };
