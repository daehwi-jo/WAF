package main

/*
import (
	"net/http"

	"charlie/i0.0.2/cls"
	"github.com/julienschmidt/httprouter"
)

// 로그인 아이디 패스워크 검증 함수.
func checkIdPass(id, pass string, h http.ResponseWriter) bool {

	var result int

	procName := "CALL proc_bo_login('" + id + "','" + pass + "');"
	lprintf(4, "[INFO] procName : %s\n", procName)
	rows, err := cls.DBc.Query(procName)
	if err != nil {
		lprintf(1, "[ERR ] %s call error : %s\n", procName, err)
		cls.Renderer.HTML(h, http.StatusInternalServerError, "warning", nil)
		return false
	}
	defer rows.Close()

	// 응답코드 check
	for rows.Next() {
		if err := rows.Scan(&result); err != nil { // function error
			lprintf(1, "[ERR ] %s first return scan error : %s\n", procName, err)
		} else if result == 99 { // 프로시저 에러
			lprintf(1, "[ERR ] dbms error %s : %d\n", procName, result)
		} else if result != 0 { // 저장 조건에 충족하지 않아서 에러
			lprintf(1, "[ERR ] %s is not satisfied with conditions : %d\n", procName, result)
		} else { // login success
			return true
		}
	}

	// 프로시저 에러
	cls.Renderer.HTML(h, http.StatusInternalServerError, "warning", nil)
	return false
}

// 로그인 시도하면 호출 되는 함수.
func FnLogin(h http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	userId := r.FormValue("userId")
	userPw := r.FormValue("userPw")

	lprintf(4, "[INFO] userId : %s, userPw : %s\n", userId, userPw)
	if checkIdPass(userId, userPw, h) {
		lprintf(4, "[INFO] login success\n")

		//cls.SuccLogin(h, r, userId)		// login 성공 후 이전페이지로 이동
		cls.SuccLoginPage(h, r, userId, "") // login 성공 후 지정페이지로 이동

	} else {
		lprintf(4, "[INFO] login fail\n")
		cls.FailLogin(h, r, int(1)) // 1: InternalServerError else StatusFound return
	}
}

// Warning 페이지.
func Warning(h http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	cls.Renderer.HTML(h, http.StatusOK, "warning", nil)
}
*/
