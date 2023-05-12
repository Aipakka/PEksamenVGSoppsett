const express=require("express");
const bcrypt=require("bcryptjs"); 
const path=require("path");
const db=require("better-sqlite3")("ProveEksamen.db");
const session = require("express-session");
const app=express();
const hbs = require("hbs")


app.use(express.urlencoded({extended: true}));

//finner public mappen
const publicPath=path.join(__dirname, "/Public");
app.use(express.static(publicPath));

//setter hbs som view engine
app.set("view engine", hbs);
app.set("views", path.join(__dirname, "./Views/Pages"))
hbs.registerPartials(path.join(__dirname, "./Views/Partials"))

//forbereder session
app.use(session({
    secret: "ú9εφνφθθφ32!@διæÆιφδςδσE7FÉfEHFsssZ<<><fsdhght//(=?=)F90fisdIFi99øå030932£sdfdffhdσσδφγaadkfsdDdvu56578UOφσσσδMD£$ØÅÅØÅææøæåøæφσ£%éweWWEFGD$IUUI!!σ9σr9δφasdddasSASFrasDαδσglfhASS",
    resave: false,
    saveUninitialized: false 
}));

app.get("/", (req, res)=> {
    res.redirect("/index.html");
});

app.post("/LoggIn", async (req, res) => {
    let svar = req.body;
    let data = db.prepare("SELECT * FROM Person WHERE Person.Epost = ?").get(svar.Epost);
    if(data){//sjekker at bruker finnes
        if(await bcrypt.compare(svar.password, data.PassordHash)){//samenligner passord med databasen
            let userData= data;

            //lagre brukerdata i sessionen
            req.session.loggedin = true;
            req.session.userData = userData;
            req.session.admin = false;
            req.session.klasseData = db.prepare("SELECT * FROM Klasse WHERE Klasse.id = ?").get(userData.Klasse_id);

            if(userData.rolle == "Admin"){
                req.session.admin = true;
            }
            res.redirect("/Profil");
        }else{         
            res.send('<script>alert("Feil Epost eller Passord"); location.href = "/loggIn.html"; </script>');
        }
    }else{
        res.send('<script>alert("Feil Epost eller Passord"); location.href = "/loggIn.html"; </script>');

    }
});
app.get("/Profil", (req, res)=>{
    if(req.session.loggedin){
      

        res.render("Profil.hbs", {
            userdata: req.session.userData,
            klasseData: req.session.klasseData,
            Admin: req.session.admin
        })
    }
    else{
        res.redirect("/index.html");
    }
}
);
app.get("/CreateUserForm", (req, res)=>{
    if(req.session.loggedin && req.session.admin){
        klasser= db.prepare("SELECT * FROM Klasse").all();
        res.render("CreateUserForm.hbs",{
            Admin: req.session.admin,
            klasser: klasser
        })
    }else{
        res.redirect("/index.html");
    }
});
app.post("/CreateUser", async (req,res)=>{
    let svar= req.body
    if(svar.rolle == "Elev"){
        if(svar.klasse!="Ingen"){
            let hash = await bcrypt.hash(svar.password, 10)
            let generatedusername = svar.fornavn.substring(0, 3) + svar.etternavn.substring(0, 3) + svar.tlf.toString().substr(0, 3);
            db.prepare(`INSERT INTO Person (rolle,Fornavn,Etternavn,Epost,tlf,Personnummer,Klasse_id,PassordHash, Adresse, Brukernavn) 
            VALUES (?,?,?,?,?,?,?,?,?,?);`).run(svar.rolle, svar.fornavn, svar.etternavn, svar.epost, svar.tlf, svar.personnummer, svar.klasse, hash, svar.Adresse, generatedusername)
        }else{
            res.send('<script>alert("Elever må være i en klasse"); location.href = "/CreateUserForm"; </script>');
        }
    }else{
        let hash = await bcrypt.hash(svar.password, 10)
        let generatedusername = svar.fornavn.substring(0, 3) + svar.etternavn.substring(0, 3) + svar.tlf.toString().substr(0, 3);
        db.prepare(`INSERT INTO Person (rolle,Fornavn,Etternavn,Epost,tlf,Personnummer,PassordHash, Adresse, Brukernavn) 
        VALUES (?,?,?,?,?,?,?,?,?);`).run(svar.rolle, svar.fornavn, svar.etternavn, svar.epost, svar.tlf, svar.personnummer, hash, svar.Adresse, generatedusername)
    }

    res.send('<script>alert("Bruker lagt til"); location.href = "/CreateUserForm"; </script>');
});
app.get("/Loggout", (req, res) => {
    //fjern sessionen
    req.session.destroy();
    res.redirect("/");
})
app.get("/changePwd", (req, res)=>{
    if(req.session.loggedin){

        res.render("UpdatePwd.hbs", {
            Admin: req.session.admin
        })
    }else{
        res.redirect("/index.html");
    }
})

app.post("/updpwd", async (req,res)=>{
    let svar = req.body;
    if(await bcrypt.compare(svar.oldpassword, req.session.userData.PassordHash)){
        let hash = await bcrypt.hash(svar.newpassword, 10)
        db.prepare("UPDATE Person SET PassordHash = ? WHERE id = ?").run(hash, req.session.userData.id)
        res.send('<script>alert("Passord oppdatert"); location.href = "/Profil"; </script>');
    }
});


app.listen(3000,()=>{
    console.log("Running at 3000")
})