import { Router } from 'express';
import authorController from '../controllers/auth.controller';
import { verifyToken } from '../middlewares/auth.middleware';
import { refreshTokenLimiter } from '../middlewares/limitRequest';
const router = Router();
router.post('/register', authorController.register);
router.post('/login', authorController.login);
router.post('/refresh', refreshTokenLimiter, authorController.requestRefreshToken);
router.get('/logout', verifyToken, authorController.logout);
export default router;
