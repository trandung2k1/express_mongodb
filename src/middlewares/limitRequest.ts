import rateLimit from 'express-rate-limit';
export const refreshTokenLimiter = rateLimit({
    windowMs: 14 * 60 * 1000,
    max: 2,
    standardHeaders: true,
    legacyHeaders: false,
});
