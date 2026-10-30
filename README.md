# Share-safe backup export

이 폴더는 Hospital DR Repository 전체를 그대로 공유하기 위한 복사본이 아니라, 코드·문서·설정 템플릿만 모은 공유용 export이다.

포함 영역:

- `db/`
- `emr/`
- `msp/`
- `web/`
- `physical/`
- `gns3/`

DB dump, SQL 데이터, 암호화 backup, 실제 `.env`, private key, certificate key, access log, 환자/운영 runtime 데이터, legacy Firebase backup, Git metadata와 과거 백업은 포함하지 않는다. DB 계정·변수 inventory도 제외한다. 복사본의 token, password, credential, AWS 식별자와 네트워크 주소는 placeholder로 치환한다.

이 폴더는 기존 Repository의 Git 이력과 분리해서 공유해야 한다. 기존 Repository 안에 추가 commit하여 공개하면 기존 `db/`, `emr/`, `web/` 파일과 Git 과거 이력까지 함께 노출될 수 있으므로, 별도 private Repository 또는 archive로 전달한다.

placeholder로 치환된 값은 공유용이며 운영 복원에 바로 사용할 수 없다. 실제 secret과 운영 환경값은 별도 secret store에서 주입한다.
