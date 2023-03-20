import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import sequelize from './dbconfig.js';
import jwt from 'jsonwebtoken';
dotenv.config();

const server = express();
const port = process.env.PORT || 3000;

server.use(express.json());
server.use(cors());

server.post('/token', async (req, res) => {
	const { refreshToken } = req.body;

	if (!refreshToken) return res.status(422);

	const refreshTokenQuery = '%' + refreshToken + '%';

	const query = await sequelize.query(
		'SELECT userId, role, refreshToken FROM users WHERE refreshToken LIKE :refreshToken',
		{
			replacements: { refreshToken: refreshTokenQuery },
			type: sequelize.QueryTypes.SELECT
		}
	);

	if (query == false)
		return res.status(401).json({
			success: false,
			status: 401,
			message: 'Você não tem permissão.'
		});

	const userId = query[0].userId;
	const role = query[0].role;

	let userTokens = JSON.parse(query[0].refreshToken);
	const index = userTokens.findIndex((item) => item === refreshToken);
	const token = userTokens[index];

	try {
		jwt.verify(token, process.env.SECRET_REFRESH_TOKEN);

		const newToken = jwt.sign(
			{ userId, role },
			process.env.SECRET_ACCESS_TOKEN,
			{
				expiresIn: '15min'
			}
		);

		return res.status(200).json({
			success: true,
			status: 200,
			message: 'OK',
			accessToken: newToken
		});
	} catch (error) {
		
		userTokens.splice(index, 1);
		userTokens = JSON.stringify(userTokens);

		const query = await sequelize.query(
			'UPDATE users SET refreshToken = :userTokens WHERE userId = :userId',
			{
				replacements: { refreshToken: userTokens, userId: userId },
				type: sequelize.QueryTypes.UPDATE
			}
		);

		return res.status(401).json({
			success: false,
			status: 401,
			message: 'Você não tem permissão.'
		});
	}
});

server.listen(port, () => {
	console.log(`Servidor rodando na porta ${port}`);
});
