import { Injectable } from '@angular/core';
import {
  HttpEvent,
  HttpInterceptor,
  HttpHandler,
  HttpRequest,
  HttpErrorResponse,
} from '@angular/common/http';
import { Observable, throwError, BehaviorSubject } from 'rxjs';
import { catchError, filter, switchMap, take } from 'rxjs/operators';
const TOKEN_HEADER_KEY = 'x-access-token';
import { AuthService } from '@core/services/auth';
// SERVICES
import { LoadingSpinnerService } from '@core/services/common';
@Injectable()
export class ErrorInterceptor implements HttpInterceptor {
  private isRefreshing = false;
  private refreshTokenSubject: BehaviorSubject<any> = new BehaviorSubject<any>(
    null
  );
  constructor(
    private spinnerService: LoadingSpinnerService,
    private authService: AuthService
  ) {}
  intercept(request: HttpRequest<any>, next: HttpHandler): Observable<any> {
    return next.handle(request).pipe(
      catchError((error: HttpErrorResponse) => {
        let errorMessage = '';
        var unauthorized = false;
        if (
          error &&
          !request.url.includes('auth/login') &&
          error.status === 401
        ) {
          unauthorized = true;
        }
        if (error.error instanceof ErrorEvent) {
          //  frontend error
          errorMessage = `Error: ${error.error.message}`;
        } else {
          // backend error
          errorMessage = error.error || error.message;
        }
        this.spinnerService.removeQuene();
        return unauthorized
          ? this.handle401Error(request, next)
          : throwError({ status: error.status, message: errorMessage });
      })
    );
  }
  handle401Error(request: HttpRequest<any>, next: HttpHandler) {
    if (!this.isRefreshing) {
      this.isRefreshing = true;
      this.refreshTokenSubject.next(null);
      const token = localStorage.getItem('accessToken');
      if (token)
        return this.authService.refreshToken(token).pipe(
          switchMap((token: any) => {
            this.isRefreshing = false;
            localStorage.setItem('accessToken', token?.accessToken);
            this.authService.setCookies(
              token?.accessToken,
              localStorage.getItem('email') || ''
            );
            this.refreshTokenSubject.next(token.accessToken);

            return next.handle(this.addTokenHeader(request, token.accessToken));
          }),
          catchError((err) => {
            this.isRefreshing = false;

            this.authService.logOut();
            return throwError(err);
          })
        );
    }
    return this.refreshTokenSubject.pipe(
      filter((token) => token !== null),
      take(1),
      switchMap((token) => next.handle(this.addTokenHeader(request, token)))
    );
  }
  private addTokenHeader(request: HttpRequest<any>, token: string) {
    /* for Spring Boot back-end */
    // return request.clone({ headers: request.headers.set(TOKEN_HEADER_KEY, 'Bearer ' + token) });
    /* for Node.js Express back-end */
    return request.clone({
      headers: request.headers.set(TOKEN_HEADER_KEY, token),
    });
  }
}
