package br.org.generation.farmacia.model;

import java.util.List;

import javax.persistence.CascadeType;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@Entity
@Table(name = "tb_categoria")
public class Categoria {
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private long idCateg;
	
	@NotBlank(message = "O nome é obrigatório")
	@Size(min = 2, max = 60, message = "O nome deve conter entre 2 a 60 caracteres")
	private String nomeCateg;
	
	@NotBlank(message = "A descrição é obrigatória")
	@Size(min = 2, max = 600, message = "A descrição deve conter entre 2 a 600 caracteres")
	private String descricaoCateg;
	
	@OneToMany(mappedBy = "categoria", cascade = CascadeType.ALL)
	@JsonIgnoreProperties("categoria")
	private List<Produto> produto;

	public long getIdCateg() {
		return idCateg;
	}

	public void setIdCateg(long idCateg) {
		this.idCateg = idCateg;
	}

	public String getNomeCateg() {
		return nomeCateg;
	}

	public void setNomeCateg(String nomeCateg) {
		this.nomeCateg = nomeCateg;
	}

	public String getDescricaoCateg() {
		return descricaoCateg;
	}

	public void setDescricaoCateg(String descricaoCateg) {
		this.descricaoCateg = descricaoCateg;
	}

	public List<Produto> getProduto() {
		return produto;
	}

	public void setProduto(List<Produto> produto) {
		this.produto = produto;
	}

}
