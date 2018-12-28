import {Injectable} from '@angular/core';
import {HttpClient, HttpHeaders} from "@angular/common/http";
import {JwtHelperService} from "@auth0/angular-jwt";
import {map} from "rxjs/operators";

@Injectable({
  providedIn: 'root'
})
export class LoginService {

  private _jwt: Jwt;

  constructor(private http: HttpClient,
              // private helperService: JwtHelperService
  ) {
  }

  login(loginRequest: LoginRequest) {
    let body: URLSearchParams = new URLSearchParams();
    body.set('username', loginRequest.username);
    body.set('password', loginRequest.password);

    const options = {
      headers: new HttpHeaders({
        'Content-type': 'application/x-www-form-urlencoded',
        'Authorization': 'Basic ' + btoa("public-call:public")
      })
    };

    let url = 'http://localhost:9000/auth-server/oauth/token?grant_type=password';
    return this.http.post(url, body.toString(), options)
      .pipe(
        map((res: Jwt) => {
          this._jwt = res;
          sessionStorage.setItem('access_token', res.access_token);
          let helperService = new JwtHelperService();
          console.log(helperService.decodeToken(res.access_token));
          console.log(res.access_token);
          return true;
        })
      );
  }
}

export class LoginRequest {
  username: string;
  password: string;
}

export class Jwt {
  access_token: string;
  token_type: string;
  refresh_token: string;
  expires_in: number;
  scope: string;
  jti: string;
}
//cHVibGljLWNhbGw6cHVibGlj
//cHVibGljLWNhbGw6cHVibGlj
