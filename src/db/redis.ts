import { createClient } from 'redis';
import colors from 'colors';
const redisClient = createClient();
redisClient.on('error', (err: Error): void => {
    console.log(err);
    console.log(colors.red('Redis Client Error'));
    process.exit(1);
});
redisClient.on('connect', (): void => {
    console.log(colors.green('Redis plugged in.'));
});
(async (): Promise<void> => {
    await redisClient.connect();
})();

export default redisClient;
