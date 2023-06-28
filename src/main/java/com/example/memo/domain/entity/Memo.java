package com.example.memo.domain.entity;

import com.example.memo.dto.request.MemoRequestDto;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity // JPA가 관리할 수 있는 Entity 클래스 지정
@Table(name = "memo") // 매핑할 테이블의 이름을 지정
@Getter
@Setter
@NoArgsConstructor
public class Memo {
	@Id
	private Long id;

	// nullable: null 허용 여부
	// unique: 중복 허용 여부 (false 일때 중복 허용)
	@Column(name = "username", nullable = false, unique = true)
	private String username;

	// length: 컬럼 길이 지정
	@Column(name = "contents", nullable = false, length = 500)
	private String contents;

	public Memo(MemoRequestDto requestDto) {
		this.username = requestDto.getUsername();
		this.contents = requestDto.getContents();
	}
}