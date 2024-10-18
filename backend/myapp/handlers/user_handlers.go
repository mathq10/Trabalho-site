package handlers

import (
    "context"
    "encoding/json"
    "net/http"
    "github.com/gorilla/mux"
    "go.mongodb.org/mongo-driver/bson"
    "go.mongodb.org/mongo-driver/bson/primitive"
    "gitlab.com/mathq10/ps-backend-Joao-Holanda-Matheus-Queiros/db"
    "gitlab.com/mathq10/ps-backend-Joao-Holanda-Matheus-Queiros/models"
    "golang.org/x/crypto/bcrypt"
    "github.com/golang-jwt/jwt/v4"
    "time"
    
    
)

func GetUsers(w http.ResponseWriter, r *http.Request) {
    var users []models.User
    cursor, err := db.UserCollection.Find(context.Background(), bson.M{})
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer cursor.Close(context.Background())
    for cursor.Next(context.Background()) {
        var user models.User
        cursor.Decode(&user)
        users = append(users, user)
    }
    json.NewEncoder(w).Encode(users)
}


func HashPassword(password string) (string, error) {
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    if err != nil {
        return "", err
    }
    return string(hashedPassword), nil
}

func CreateUser(w http.ResponseWriter, r *http.Request) {
    var user models.User
    err := json.NewDecoder(r.Body).Decode(&user)
    if err != nil {
        http.Error(w, "Erro ao decodificar a solicitação", http.StatusBadRequest)
        return
    }

    // Gerar o hash da senha
    hashedPassword, err := HashPassword(user.Password)
    if err != nil {
        http.Error(w, "Erro ao gerar o hash da senha", http.StatusInternalServerError)
        return
    }
    
    user.Password = hashedPassword // Atualiza o campo de senha com o hash
    user.ID = primitive.NewObjectID()
    
    _, err = db.UserCollection.InsertOne(context.Background(), user)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // Retorna o usuário criado, incluindo a senha (não recomendado em produção)
    json.NewEncoder(w).Encode(user)
}



func GetUser(w http.ResponseWriter, r *http.Request) {
    params := mux.Vars(r)
    id, err := primitive.ObjectIDFromHex(params["id"])
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    var user models.User
    err = db.UserCollection.FindOne(context.Background(), bson.M{"_id": id}).Decode(&user)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    json.NewEncoder(w).Encode(user)
}

func UpdateUser(w http.ResponseWriter, r *http.Request) {
    params := mux.Vars(r)
    id, err := primitive.ObjectIDFromHex(params["id"])
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    var user models.User
    json.NewDecoder(r.Body).Decode(&user)
    _, err = db.UserCollection.UpdateOne(context.Background(), bson.M{"_id": id}, bson.M{"$set": user})
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    json.NewEncoder(w).Encode(user)
}

func DeleteUser(w http.ResponseWriter, r *http.Request) {
    params := mux.Vars(r)
    id, err := primitive.ObjectIDFromHex(params["id"])
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    _, err = db.UserCollection.DeleteOne(context.Background(), bson.M{"_id": id})
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    w.WriteHeader(http.StatusNoContent)
}

// Função de geração de token JWT
func GenerateJWT(userEmail string) (string, error) {
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "email": userEmail,
        "exp":   time.Now().Add(time.Hour * 24).Unix(),
    })
    tokenString, err := token.SignedString([]byte("seuSegredo"))
    if err != nil {
        return "", err
    }
    return tokenString, nil
}

func Login(w http.ResponseWriter, r *http.Request) {
    var user models.User
    var foundUser models.User
    err := json.NewDecoder(r.Body).Decode(&user)
    if err != nil {
        http.Error(w, "Erro ao decodificar os dados do usuário", http.StatusBadRequest)
        return
    }

    // Procurar o usuário pelo e-mail
    err = db.UserCollection.FindOne(context.Background(), bson.M{"email": user.Email}).Decode(&foundUser)
    if err != nil {
        http.Error(w, "Usuário ou senha incorretos", http.StatusUnauthorized)
        return
    }

    // Verificar a senha
    err = bcrypt.CompareHashAndPassword([]byte(foundUser.Password), []byte(user.Password))
    if err != nil {
        http.Error(w, "Usuário ou senha incorretos", http.StatusUnauthorized)
        return
    }

    // Gerar JWT
    token, err := GenerateJWT(foundUser.Email)
    if err != nil {
        http.Error(w, "Erro ao gerar token", http.StatusInternalServerError)
        return
    }

    // Retornar o token e o nome do usuário
    json.NewEncoder(w).Encode(map[string]string{
        "message": "Login bem-sucedido",
        "token":   token,
        "name":    foundUser.Name,
    })
}
