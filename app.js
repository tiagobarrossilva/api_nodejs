// importações
require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const Usuario = require('./model/Usuario')

const app = express()

// necessario para utilizar json na resposta
app.use(express.json())

// obtendo usuario e senha do arquivo .env para o banco de dados
const usuariodb = process.env.DB_USER
const senhadb = process.env.DB_PASS

// conectar ao mongo db
// em connect é informado o endereço do banco de dados junto com o nome de usuario e senha
mongoose.connect(`mongodb+srv://${usuariodb}:${senhadb}@cluster0.wozhnwh.mongodb.net/?retryWrites=true&w=majority`,)
.then(() =>{
    app.listen(3000)
    console.log('conectou ao banco')
})
.catch((err) => console.log(err))

// função para verificar token que vem do frontend
function checkToken(req,res,next){
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]
    if(!token){
        return res.status(401).json({msg: 'acesso negado'})
    }
    try{
        const secret = process.env.SECRET
        jwt.verify(token,secret)
        next()
    }catch(error){
        return res.status(401).json({msg: 'token invalido'})
    }
}

// ============================== rotas ==============================

// rota privada, consultar por id
app.get("/usuario/:id",checkToken, async(req,res) =>{
    // obtendo id que vem na url
    const id = req.params.id

    const objUsuario = await Usuario.findById(id, '-senha')

    if(!objUsuario){
        return res.status(404).json({msg: "usuario não encontrado"})
    }
    else{
        return res.status(200).json({msg: objUsuario})
    }
})

// rota pagina inicial
app.get('/',(req,res) =>{
    res.status(200).json({msg: "testando"})
})

// rota cadastra novo usuario
app.post('/cadastrar_usuario', async(req,res) =>{
    const {nome,email,senha,confirmarsenha} = req.body
    if(!nome){
        return res.status(422).json({msg: "faltou digitar o nome"})
    }
    if(!email){
        return res.status(422).json({msg: "faltou digitar o email"})
    }
    if(!senha){
        return res.status(422).json({msg: "faltou digitar a senha"})
    }
    if(senha != confirmarsenha){
        return res.status(422).json({msg: "as senhas estão diferentes"})
    }

    // verificar se o usuario existe no banco de dados
    const usuarioEmail = await Usuario.findOne({email: email})
    if(usuarioEmail){
        return res.status(422).json({msg: "esse email ja existe, use outro"})
    }

    // gerar senha criptografada a partir da senha que o usuario digitou
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(senha,salt)

    // criar um objeto do tipo usuario com os parametros que serão salvos no banco
    // nesse exemplo onde são informadas apenas o nome das variaveis é por que elas coincidem com o nome dos campos chaves
    const objUsuario = new Usuario({nome,email,senha:passwordHash})

    // armazenar os dados de objUsuario no banco de dados
    try{
        objUsuario.save()
        res.status(201).json({msg: "usuario armazenado"})
    }catch(erro){
        console.log(erro)
        res.status(500).json({msg: "ocorreu um erro, o usuario não foi armazenado"})
    }
})

// rota fazer login
app.post('/login', async(req,res) =>{
    const {email,senha} = req.body
    if(!email){
        return res.status(422).json({msg: "faltou digitar o email"})
    }
    else{
        if(!senha){
            return res.status(422).json({msg: "faltou digitar a senha"})
        }
        else{
            // consultando no banco de dados
            const objUsuario = await Usuario.findOne({email: email})

            if(objUsuario){
                const checkPassword = await bcrypt.compare(senha,objUsuario.senha)
                if(checkPassword){
                    console.log("login autorizado")
                }
                else{
                    return res.status(422).json({msg: "senha invalida"})
                }
                // longin bem sucedido
                try{
                    const secret = process.env.SECRET
                    const token = jwt.sign(
                        {
                            id: objUsuario._id,
                        },
                        secret,
                    )
                    res.status(200).json({msg: "autenticado",token})
                }catch(err){
                    return res.status(422).json({msg: "erro no servidor"})
                }
            }
            else{
                //usuario não encontrado
                return res.status(422).json({msg: "email não encontrado"})
            }
        }
    }
})