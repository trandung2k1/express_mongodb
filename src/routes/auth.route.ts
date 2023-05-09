import { Router } from 'express';
import authorController from '../controllers/auth.controller';
const router = Router();
router.post('/register', authorController.register);
router.post('/login', authorController.login);
router.post('/refresh', authorController.requestRefreshToken);
router.get('/logout', authorController.logout);
export default router;
