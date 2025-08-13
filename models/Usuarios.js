require('dotenv').config();

const bcrypt = require('bcrypt');

const ROUNDS = Number(process.env.ROUNDS)

class Usuario {
    constructor(usuario, senha, descricao) {
        this.usuario = usuario;
        this.descricao = descricao;
        this.senha = senha;
    }

    static async criar(usuario, senha,descricao) {
        let senhaHash = await bcrypt.hash(senha, ROUNDS);
        return new Usuario(usuario, senhaHash, descricao);
    }
}

module.exports = Usuario;