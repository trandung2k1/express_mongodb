import { Router } from 'express';
import userController from '../controllers/user.controller';
import { verifyToken } from '../middlewares/auth.middleware';
const router: Router = Router();
router.get('/', verifyToken, userController.getAllUser);
export default router;
