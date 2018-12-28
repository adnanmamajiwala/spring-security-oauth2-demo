import {Component, OnInit} from '@angular/core';
import {LoginService} from "./login.service";
import {FormControl, FormGroup, Validators} from "@angular/forms";

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css']
})
export class AppComponent implements OnInit {

  loginForm: FormGroup;

  constructor(private loginService: LoginService) {
  }

  ngOnInit(): void {
    this.loginForm = new FormGroup({
      username: new FormControl('', Validators.required),
      password: new FormControl('', Validators.required)
    })
  }

  onLogin() {
    if (this.loginForm.valid) {
      console.log('about to call login service ---', this.loginForm.value);
      this.loginService.login(this.loginForm.value)
        .subscribe(() => {

        });
    } else {
      console.log('Not Valid');
    }
  }
}
