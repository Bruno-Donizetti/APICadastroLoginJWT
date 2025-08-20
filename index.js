// .ENV
require('dotenv').config();
const PORT = process.env.PORT;
const URI = process.env.URI;
const DB_NAME = process.env.DB_NAME;
const COLLECTION = process.env.COLLECTION;
const JWT_SECRET = process.env.JWT_SECRET;

// JWT
const jwt = require('jsonwebtoken');

// bcrypt
const bcrypt = require('bcrypt');

// Classes
const Usuario = require('./models/Usuarios')

//cors
const cors = require('cors');
// EXPRESS
const express = require('express');
const app = express();
app.use(express.json());
app.use(cors());
// MONGODB

const {MongoClient, ObjectId} = require('mongodb');
// let client = await MongoClient.connect(URI);
let client;
(async () => {
    client = await MongoClient.connect(URI);
})();

// HTML-ESCAPE
const escape = require('html-escape');

// ROTAS
app.post('/cadastrar', async (req, res) => {
    const {usuario, senha, confirmarSenha, descricao} = req.body;
    if (!usuario || !senha || !confirmarSenha || !descricao) {
        return res.status(400).json({message:"Preencha todos os campos."});
    }

    if (senha != confirmarSenha) {
        return res.status(400).json({message:"As senhas não são iguais."});
    }

    let descricaoEscape = escape(descricao);

    const db = client.db(DB_NAME);
    const collection =  db.collection(COLLECTION);

    let dados = await Usuario.criar(usuario, senha, descricaoEscape);
    
    let count = await collection.countDocuments({usuario: usuario});

    if (count > 0) {
        return res.status(409).json({message:"Usuario existente, tente outro."});
    }

    try {
        await collection.insertOne(dados);
        res.status(201).json({message:"Usuario cadastrado com sucesso!"});
    } catch (error) {
        console.log(`ERRO AO ADICIONAR USUARIO:\n${error}`);
        res.status(500).json({message:"Erro ao adicionar usuario."});
    }
});

app.post('/login', async (req, res) => {
    const {usuario, senha} = req.body;

    if (!usuario || !senha) {
        return res.status(400).json({ message : "Preencha todos os campos."});
    }

    const db = client.db(DB_NAME);
    const collection = db.collection(COLLECTION);

    let count = await collection.countDocuments({usuario : usuario});

    if (count == 0) {
        return res.status(401).json({message : 'Usuario ou senha inválidos.'});
    }

    let dados = await collection.findOne({usuario : usuario});

    let verify = await bcrypt.compare(senha,dados.senha);
    
    if (verify) {
        let token = jwt.sign({_id: dados._id}, JWT_SECRET, {expiresIn: '1h'});

        return res.status(200).json({token : token});     
    }

    res.status(401).json({message : 'Usuario ou senha inválidos.'});
});

app.get('/dados', async (req, res) => {
    const auth = req.headers.authorization;
    const token = auth.split(' ')[1];
    let decode;
    try {
        decode = jwt.verify(token, JWT_SECRET);
    }catch(error){
        return res.send('Token invalido.')
    }

    const db = client.db(DB_NAME);
    const collection = db.collection(COLLECTION);

    let count = await collection.countDocuments({_id: new ObjectId(decode._id)});

    if (count == 0) {
        return res.send("Usuario não encontrado.")
    }

    const dados = await collection.findOne({_id : new ObjectId(decode._id)});

    res.send({
        usuario : dados.usuario,
        descricao : dados.descricao
    });
})

app.get('/auth', async (req, res) => {
    const auth = req.headers.authorization;

    if (!auth) {
        return res.send('Token inválido.')
    }

    const token = auth.split(' ')[1];

    let verify;

    try {
        verify = jwt.verify(token, JWT_SECRET);
    } catch (error) {
        return res.status(403).send("Token inválido.")
    }

    res.status(200).send("Token válido.")
})

app.get('/verifyUser', async (req, res) => {
    const auth = req.headers.authorization;
    const JWT = auth.split(' ')[1];

    try{
        jwt.verify(JWT, JWT_SECRET);
    }catch(err){
        return res.send("Token invalido.")
    }

    const {usuario} = req.body;

    if (!usuario) {
        return res.send(false)
    }

    const idAtual = jwt.verify(JWT,JWT_SECRET)._id;

    const db = client.db(DB_NAME);
    const collection = db.collection(COLLECTION);

    try {
        const existe = await collection.countDocuments({usuario : usuario});
        const dados = await collection.findOne({_id : new ObjectId(idAtual)});
        const usuarioAtual = (dados.usuario);
        
        if (existe == 0 || usuario == usuarioAtual) {
            return res.send(true);
        }

        return res.send(false);
    }catch(err){
        return res.send("Erro na busca.")
    }
});

app.put('/atualizarDados', async (req, res) => {
    const {usuario, descricao} = req.body;
    const auth = req.headers.authorization;
    const JWT = auth.split(' ')[1];
    const dadosJWT = jwt.verify(JWT, JWT_SECRET);

    const db = client.db(DB_NAME);
    const collection = db.collection(COLLECTION);

    const _id = dadosJWT._id;

    const dados = await collection.findOne({_id : new ObjectId(_id)});

    const count = await collection.countDocuments({usuario : usuario});
    
    if (count == 0 || usuario == dados.usuario) {
        await collection.updateOne({_id : new ObjectId(_id)},{$set:{
            usuario : usuario,
            descricao : escape(descricao)
        }});

        return res.send("Dados alterados");
    }

    res.send("Nome de usuario indisponivel")
});

app.delete('/deletarUsuario', async (req, res) => {
    const auth = req.headers.authorization;
    const JWT = auth.split(' ')[1];

    try {
        jwt.verify(JWT, JWT_SECRET);
    } catch (error) {
        return res.send("Token invalido");
    }

    const dadosJWT = jwt.verify(JWT, JWT_SECRET);
    const _idUser = dadosJWT._id;

    const db = client.db(DB_NAME);
    const collection = db.collection(COLLECTION);

    try {
        const d = await collection.deleteOne({
            _id: new ObjectId(_idUser)
        });

        if (d.deletedCount > 0) {
            return res.send(`Usuario com id ${_idUser} deletado`);
        }else{
            return res.send("Usuario não encontrado")
        }
    } catch (error) {
        console.log(error);
        
        return res.send("Usuario não encontrado");
    }

})

app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});